reset
set terminal postscript enhanced font "Helvetica,28"
set size ratio 0.7
figure_dir = "./figures"
data_dir = "./output"
set output figure_dir."/2013.08.19.40utmachines.seg_size.eps"
set xlabel "interval (seconds)" font "Helvetica,28"
set ylabel "clock skew stdev" font "Helvetica,28"
set tics font "Helvetica,28"
set yrange [*:1.8]
set xtics 0,300,1800
set xtics rotate by -90

#set key Left over reverse nobox spacing 1
set key right top
#set nokey

set style line 1 lc rgb "#FF0000" lt 1 lw 3
set style line 2 lc rgb "#0000FF" lt 2 lw 3
set style line 3 lc rgb "orange" lt 3 lw 3
set style line 4 lc rgb "green" lt 4 lw 3
set style line 5 lc rgb "yellow" lt 5 lw 3
set style line 6 lc rgb "black" lt 6 lw 3

plot data_dir."/2013.08.19.40utmachines.seg_size.txt" using 1:2 with linespoints ls 1 title "machine 1", \
     "" using 1:3 with linespoints ls 2 title "machine 2", \
     "" using 1:4 with linespoints ls 3 title "machine 3", \
     "" using 1:5 with linespoints ls 4 title "machine 4", \
     "" using 1:6 with linespoints ls 5 title "machine 5", \
     "" using 1:7 with linespoints ls 6 title "machine 6"
