reset
set terminal postscript enhanced
set size ratio 0.7

file_name = "tethered_IP"
set output file_name.".eps"

set title "# of Tethered IPs"
set xlabel "number of tethered IP"
set ytics nomirror
set ylabel "CDF (%)"
set key right bottom
# set key Left under reverse nobox spacing 1
# set nokey

set style line 1 lc rgb "#FF0000" lt 1 lw 3
set style line 2 lc rgb "#0000FF" lt 1 lw 3
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot "data_all_src.txt" using 2:1 with linespoints ls 1 title "tethered IP"


################################################

reset
set terminal postscript enhanced
set size ratio 0.7

file_name = "all_IP"
set output file_name.".eps"

set title "# of all IPs"
set xlabel "number of IPs"
set ytics nomirror
set ylabel "CDF (%)"
set key right bottom
# set key Left under reverse nobox spacing 1
# set nokey

set style line 1 lc rgb "#FF0000" lt 1 lw 3
set style line 2 lc rgb "#0000FF" lt 1 lw 3
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot "data_all_src.txt" using 3:1 with linespoints ls 1 title "all IP"


################################################

reset
set terminal postscript enhanced
set size ratio 0.7

file_name = "ratio_IP"
set output file_name.".eps"

set title "# tethered IPs / # all IPs"
set xlabel "ratio"
set ytics nomirror
set ylabel "CDF (%)"
set key right bottom
# set key Left under reverse nobox spacing 1
# set nokey

set style line 1 lc rgb "#FF0000" lt 1 lw 3
set style line 2 lc rgb "#0000FF" lt 1 lw 3
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot "data_all_src.txt" using 4:1 with linespoints ls 1 title "ratio of # tethered IPs to # all IPs"


