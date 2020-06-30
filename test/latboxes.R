#
# Plots latency box plots for the latency comparison.
#
require(extrafont)
require(ggplot2)
require(ggpubr)

# disable scientific notiation when labeling axis
options(scipen=999)

# colors as they are computed by ggplot2 (function is from stackoverflow)
gg_color_hue = function(n) {
    hues = seq(15, 375, length = n + 1)
    hcl(h = hues, l = 65, c = 100)[1:n]
}

#
# configuration constants
#
modes       = c("randread", "read", "randwrite", "write");
bsizes      = c("4k", "64k", "1024k");
title_bsize = c("4 KiB", "64 KiB", "1024 KiB")
xlabs       = c("local", "nvmf", 
                "crdss\n(block)", "crdss\n(poll)")

args   = commandArgs(trailingOnly = TRUE)
if (length(args) < 5) {
    stop("provide at least 4 directories and an output file.\n", call.=FALSE)
}

ldir  = args[1];            # local
ndir  = args[2];            # nvmf
cbdir = args[3];            # crdss, blocking
cpdir = args[4];            # crdss, polling

for (mode in modes) {
    local  = read.csv(paste(ldir, mode, "/latstat.csv", sep = ""), 
                      header = TRUE, sep = ",")
    nvmf   = read.csv(paste(ndir, mode, "/latstat.csv", sep = ""), 
                      header = TRUE, sep = ",")
    crdssb = read.csv(paste(cbdir, mode, "/latstat.csv", sep = ""), 
                      header = TRUE, sep = ",")
    crdssp = read.csv(paste(cpdir, mode, "/latstat.csv", sep = ""), 
                      header = TRUE, sep = ",")

    i = 1
    for (bsize in bsizes) {
        llat  = subset(local, bs == bsize)
        nlat  = subset(nvmf, bs == bsize)
        cblat = subset(crdssb, bs == bsize)
        cplat = subset(crdssp, bs == bsize)

        type_list = xlabs

        q1s     = c(llat[,5], nlat[,5], cblat[,5], cplat[,5])
        q25s    = c(llat[,6], nlat[,6], cblat[,6], cplat[,6])
        medians = c(llat[,7], nlat[,7], cblat[,7], cplat[,7])
        q75s    = c(llat[,8], nlat[,8], cblat[,8], cplat[,8])
        q99s    = c(llat[,9], nlat[,9], cblat[,9], cplat[,9])
        data    = data.frame(type_list, q1s, q25s, medians, q75s, q99s)

        print(data)
    
        q99max = max(q99s)
        out = ggplot(data, aes(x = factor(type_list, level = xlabs), 
                     ymin = q1s, lower = q25s, 
                     middle = medians, upper = q75s, ymax = q99s, 
                     fill = type_list)) +
              geom_boxplot(position = position_dodge(1), stat = "identity") +
              ggtitle(paste("Block Size", title_bsize[i])) + 
              theme_classic() +
              scale_y_continuous(name = "Latency [us]", expand = c(0, 0),
                                 limits = c(0, q99max)) +
              theme(text = element_text(family = "LM Roman 10", size = 10),
                    legend.key.size = unit(0.25, "cm"),
                    legend.position = "none",
                    axis.title.x = element_blank(),
                    plot.title = element_text(hjust = 0.5, size = 10),
                    axis.line = element_line(linetype = "solid"))

        # out = annotate_figure(file, left = text_grob("Bandwidth [MiB/s]",
        #                      family = "LM Roman 10", size = 10, rot = 90))

        ggsave(paste(args[5], "lat_", mode, "_", bsize, ".pdf", sep = ""),
               plot = out, device = cairo_pdf, width = 6.0,
               height = 6, units = "cm")
        
        i = i + 1
    }
}

# warnings()

