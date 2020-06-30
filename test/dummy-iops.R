#
# Plots IOPS of the CRDSS dummy server tests.
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

args   = commandArgs(trailingOnly = TRUE)

shown_param = "iops"
cur_bsize   = c("4k", "64k", "1024k")
title_bsize = c("4 KiB", "64 KiB", "1024 KiB")
output      = list()

if (length(args) < 3) {
    stop("provide at least 2 csv files and the output file.\n", call.=FALSE)
}

tcnts = c(0, 1, 2, 3, 4, 5, 6)
xlabs = rep(c("bla"), length(tcnts))

for (i in c(1 : length(tcnts))) {
    xlabs[i] = toString(2 ^ tcnts[i])
}

# use the same colors as in the grouped bar chart 
cols  = gg_color_hue(3)
print(cols)

block = read.csv(args[1], header = TRUE, sep = ",")
poll  = read.csv(args[2], header = TRUE, sep = ",")

j = 1
for (bsize in cur_bsize) {
    block_bs = subset(block, bs == bsize)
    poll_bs  = subset(poll, bs == bsize)

    type_list = c(rep("block", length(block_bs[,1])), 
                  rep("poll", length(poll_bs[,1])))
    tcnt_list = rep(tcnts, 2)
    iops_list = c(block_bs[,4] / 1000, poll_bs[,4] / 1000)
    data      = data.frame(type_list, tcnt_list, iops_list)

    print(data)
    print(xlabs)

    out = ggplot(data, aes(col = type_list, y = iops_list, x = tcnt_list)) +
          geom_line() +
          geom_point() +
          ggtitle(paste("Block Size", title_bsize[j])) +
          expand_limits(y = 0) +
          scale_x_continuous(name = "Thread Count", breaks = tcnts, 
                             labels = xlabs, expand = c(0, 0.25)) + 
          scale_y_continuous(name = "", expand = expansion(mult = c(0, 0.05))) +
          scale_colour_manual(values = cols, name = "", 
                              labels = c("block", "poll")) + 
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
file = annotate_figure(file, left = text_grob("IOPS (x1000)",
                       family = "LM Roman 10", size = 10, rot = 90),
                       bottom = text_grob("Thread Count", 
                       family = "LM Roman 10", size = 10))
ggsave(args[3], plot = file, device = cairo_pdf, width = 20, 
       height = 6, units = "cm")

# warnings()
