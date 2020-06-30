#
# Grouped bar plots for the diploma thesis
#
require(extrafont)
require(ggplot2)
require(ggpubr)

# disable scientific notiation when labeling axis
options(scipen=999)

shown_param = "bw"
cur_bsize   = c("4k", "64k", "1024k")
title_bsize = c("4 KiB", "64 KiB", "1024 KiB")
output      = list()

args   = commandArgs(trailingOnly = TRUE)

if (length(args) < 5) {
    stop("provide at least 4 csv files and an output file.\n", call.=FALSE)
}

tcnts = c(0, 1, 2, 3, 4, 5, 6)
xlabs = rep(c("bla"), length(tcnts))

for (i in c(1 : length(tcnts))) {
    xlabs[i] = toString(2 ^ tcnts[i])
}

local  = read.csv(args[1], header = TRUE, sep = ",")
nvmf   = read.csv(args[2], header = TRUE, sep = ",")
crdss  = read.csv(args[3], header = TRUE, sep = ",")
crdssp = read.csv(args[4], header = TRUE, sep = ",")

j = 1
for (bsize in cur_bsize) {
    local_bs  = subset(local, bs == bsize)
    nvmf_bs   = subset(nvmf, bs == bsize)
    crdss_bs  = subset(crdss, bs == bsize)
    crdssp_bs = subset(crdssp, bs == bsize)

    type_list  = c(rep("local", length(local_bs[,1])), 
                   rep("nvmf", length(nvmf_bs[,1])),
                   rep("crdss", length(crdss_bs[,1])),
                   rep("crdss-p", length(crdssp_bs[,1])))
    type_list  = factor(type_list, 
                 levels = c("crdss", "crdss-p", "nvmf", "local"));
    tcnt_list  = rep(tcnts, 4)
    bandwidths = c(local_bs[,3], nvmf_bs[,3], crdss_bs[,3], crdssp_bs[,3])
    data       = data.frame(type_list, tcnt_list, bandwidths)

    print(data)
    print(xlabs)

    out = ggplot(data, aes(fill = type_list, y = bandwidths, x = tcnt_list)) +
          geom_bar(position = "dodge", stat="identity") + 
          ggtitle(paste("Block Size", title_bsize[j])) +
          scale_x_continuous(name = "Thread Count", breaks = tcnts, 
                             labels = xlabs, expand = c(0, 0)) + 
          scale_y_continuous(name = "", expand = c(0, 0)) +
          scale_fill_discrete(name = "", labels = c("crdss", "crdss-p", 
                              "nvmf", "local")) + 
          theme_classic() +
          theme(text = element_text(family = "LM Roman 10", size = 10),
                legend.key.size = unit(0.25, "cm"),
                axis.title.y = element_blank(), axis.title.x = element_blank(),
                plot.title = element_text(hjust = 0.5, size = 10),
                axis.line = element_line(linetype = "solid"))
    
    output[[j]] = out
    j = j + 1
}

file = ggarrange(output[[1]], output[[2]], output[[3]], common.legend = TRUE,
                 legend = "right", nrow = 1, ncol = 3, widths = c(1, 1, 1))
file = annotate_figure(file, left = text_grob("Bandwidth [MiB/s]",
                       family = "LM Roman 10", size = 10, rot = 90),
                       bottom = text_grob("Thread Count", 
                       family = "LM Roman 10", size = 10))
ggsave(args[5], plot = file, device = cairo_pdf, width = 20, 
       height = 6, units = "cm")

# warnings()
