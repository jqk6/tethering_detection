reset
set term pngcairo
set size ratio 0.7
figure_dir = "./figures"
data_dir = "./output"
set output figure_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.png"
set xlabel "time (seconds)"
set ylabel "offset"
set nokey
set style line 1 lc rgb "#0000FF" lt 1 lw 3
set style line 2 lc rgb "#FF0000" lt 1 lw 5
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3
plot data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.3.offset.txt" using 3:6 with points ls 1 title "192.168.1.3", \
0.154716905121117*x - 0.935155649529406 ls 2 notitle, \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.offset.txt" using 3:6 with points ls 3 title "192.168.1.7", \
0.116046569607465*x - 0.939703489837255 ls 4 notitle