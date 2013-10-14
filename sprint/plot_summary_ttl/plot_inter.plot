reset
set terminal postscript enhanced
set size ratio 0.7

file_name = "intra_ratio"
set output file_name.".eps"

set title "ratio of tethered traffic / non-tethered traffic of individuals"
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

plot "data_inter_intra.txt" using 2:1 with linespoints ls 1 title "Tput", \
     "data_inter_intra.txt" using 3:1 with linespoints ls 2 title "# Pkts", \
     "data_inter_intra.txt" using 4:1 with linespoints ls 3 title "Pkt Length Entropy"


########################################################

reset
set terminal postscript enhanced
set size ratio 0.7

file_name = "inter_ratio"
set output file_name.".eps"

set title "ratio of traffic from tethered clients / traffic from non-tethered clients"
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

plot "data_inter_intra.txt" using 5:1 with linespoints ls 1 title "Tput", \
     "data_inter_intra.txt" using 6:1 with linespoints ls 2 title "# Pkts", \
     "data_inter_intra.txt" using 7:1 with linespoints ls 3 title "Pkt Length Entropy"


