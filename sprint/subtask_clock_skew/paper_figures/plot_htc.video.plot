reset
set terminal postscript enhanced font "Helvetica,28"
set size ratio 0.7
figure_dir = "./figures"
data_dir = "./output"
set output figure_dir."/2013.07.11.HTC.video.2min.pcap.txt.eps"
set xlabel "time (seconds)" font "Helvetica,28"
set ylabel "offset" font "Helvetica,28"
set tics font "Helvetica,28"
set nokey
set style line 1 lc rgb "#FF0000" lt 1 lw 5
set style line 2 lc rgb "#0000FF" lt 1 lw 3
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot data_dir."/2013.07.11.HTC.video.2min.pcap.txt.10.0.2.5.offset.txt" using 3:6 with points ls 2 notitle, \
1.63296762103926e-05*x - 0.00870390788658144 ls 1 notitle