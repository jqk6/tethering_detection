reset
set terminal postscript eps enhanced color 28
# set terminal png enhanced 28 size 800,600
# set terminal jpeg enhanced font helvetica 28
set size ratio 0.7

data_dir = "../processed_data/subtask_plot_imc14/data/"
fig_dir  = "../processed_data/subtask_plot_imc14/figures/"
file_name = "ts_ratio.cdf.os"
fig_name  = "ts_ratio.cdf.os"
set output fig_dir.fig_name.".eps"

set xlabel '{/Helvetica=28 ratio of pkts with TCP Timestamp Option}' offset character 0, 0, 0
set ylabel '{/Helvetica=28 Frac. machines with ratio > x}' offset character 0, 0, 0

set tics font "Helvetica,24"
set xtics nomirror rotate by 0
set ytics nomirror
# set format x "10^{%L}"

set xrange [0:1]
set yrange [0:1]

# set logscale x
# set logscale y

# set lmargin 4.5
# set rmargin 5.5
# set bmargin 3.7
# set tmargin 4.4

set key left bottom
# set key at 1.1,1
# set key Left above reverse nobox horizontal spacing 0.9 samplen 1.5 width -1
# set nokey

set style line 1 lc rgb "red"     lt 1 lw 5 pt 1 ps 1.5 pi -1  ## +
set style line 2 lc rgb "blue"    lt 2 lw 5 pt 2 ps 1.5 pi -1  ## x
set style line 3 lc rgb "#00CC00" lt 5 lw 5 pt 3 ps 1.5 pi -1  ## *
set style line 4 lc rgb "#7F171F" lt 4 lw 5 pt 4 ps 1.5 pi -1  ## box
set style line 5 lc rgb "#FFD800" lt 3 lw 5 pt 5 ps 1.5 pi -1  ## solid box
set style line 6 lc rgb "#000078" lt 6 lw 5 pt 6 ps 1.5 pi -1  ## circle
set style line 7 lc rgb "#732C7B" lt 7 lw 5 pt 7 ps 1.5 pi -1
set style line 8 lc rgb "black"   lt 8 lw 5 pt 8 ps 1.5 pi -1  ## triangle
set pointintervalbox 2  ## interval to a point

# plot data_dir.file_name.".txt" using 1:3 with lines ls 2 title '{/Helvetica=28 TITLE_1}', \
#      data_dir.file_name.".txt" using 1:2 with lines ls 1 notitle

plot data_dir.file_name.".txt" using 3:1 with linespoints ls 1 title '{/Helvetica=28 Android}', \
  "" using 4:1 with linespoints ls 2 title '{/Helvetica=28 iOS}', \
  "" using 5:1 with linespoints ls 3 title '{/Helvetica=28 Windows}'
     
