reset
set terminal postscript enhanced
set size ratio 0.7
figure_dir = "./figures"
data_dir = "./output"
set xlabel "Time"
set ylabel "win size"
set key Left under reverse nobox spacing 2
set xtics rotate by 315
set style line 1 lc rgb "#FF0000" ps 1 lw 3
set style line 2 lc rgb "#0000FF" ps 1 lw 3
set style line 3 lc rgb "orange" ps 1 lw 3
set style line 4 lc rgb "green" ps 1 lw 3
set style line 5 lc rgb "yellow" ps 1 lw 3
set style line 6 lc rgb "black" ps 1 lw 3
set style line 7 lc rgb "#FF0000" ps 1 lw 3
set style line 8 lc rgb "#0000FF" ps 1 lw 3
set style line 9 lc rgb "orange" ps 1 lw 3
set style line 10 lc rgb "green" ps 1 lw 3
set style line 11 lc rgb "yellow" ps 1 lw 3
set style line 12 lc rgb "black" ps 1 lw 3
set output figure_dir."/omni.out.49.eth.pcap.txt.28.253.248.254.win.eps"
plot data_dir."/omni.out.49.eth.pcap.txt.28.253.248.254.52091.74.125.224.221.443.txt" using 1:2 with linespoints ls 1 title "OS=[],Device=[],TTL=[127]", \
data_dir."/omni.out.49.eth.pcap.txt.28.253.248.254.52095.65.54.81.215.80.txt" using 1:2 with linespoints ls 2 title "OS=[],Device=[],TTL=[127]", \
data_dir."/omni.out.49.eth.pcap.txt.28.253.248.254.52099.64.233.146.10.80.txt" using 1:2 with linespoints ls 3 title "OS=[],Device=[],TTL=[127]", \
data_dir."/omni.out.49.eth.pcap.txt.28.253.248.254.52096.64.233.146.10.80.txt" using 1:2 with linespoints ls 4 title "OS=[],Device=[],TTL=[127]", \
data_dir."/omni.out.49.eth.pcap.txt.28.253.248.254.52089.74.125.224.221.443.txt" using 1:2 with linespoints ls 5 title "OS=[],Device=[],TTL=[127]"