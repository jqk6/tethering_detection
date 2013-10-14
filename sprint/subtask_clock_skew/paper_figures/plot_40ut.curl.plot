reset
set term postscript eps enhanced monochrome font "Helvetica,28"
set size ratio 0.7
figure_dir = "./figures"
data_dir = "./output"
set output figure_dir."/2013.08.19.40utmachines.pcap.txt.eps"

set xrange [0:240]

set xlabel "time (seconds)"
set ylabel "offset"

#set key Left over reverse nobox spacing 1
set key left top
#set nokey

set style line 1 lc rgb "#0000FF" lt 1 lw 3
set style line 2 lc rgb "#FF0000" lt 2 lw 3
set style line 4 lc rgb "green" lt 4 lw 3
set style line 3 lc rgb "orange" lt 3 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot data_dir."/2013.08.19.40utmachines.pcap.txt.128.83.144.188.offset.txt" using 3:6 with points ls 1 title "machine 1", \
0.000112885544154673*x - 0.00053615038287068 ls 6 notitle, \
data_dir."/2013.08.19.40utmachines.pcap.txt.128.83.144.185.offset.txt" using 3:6 with points ls 2 title "machine 2", \
0.000112605200259602*x - 0.00156514996003142 ls 6 notitle, \
data_dir."/2013.08.19.40utmachines.pcap.txt.128.83.144.196.offset.txt" using 3:6 with points ls 3 title "machine 3", \
0.000112811189274347*x - 0.00349474337986322 ls 6 notitle, \
data_dir."/2013.08.19.40utmachines.pcap.txt.128.83.144.200.offset.txt" using 3:6 with points ls 4 title "machine 4", \
0.000112617636382886*x - 0.00210748753821043 ls 6 notitle