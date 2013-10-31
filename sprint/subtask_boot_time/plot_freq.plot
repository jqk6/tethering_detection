reset
set terminal postscript enhanced
set size ratio 0.7
figure_dir = "./figures_freq"
data_dir = "./output_freq"
set xlabel "Timestamp"
set ylabel "frequency (Hz)"
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

################################
set output figure_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq.freq_ts.eps"
plot data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:2 with points ls 1 title "freq", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:3 with points ls 2 title "avg"
################################
set output figure_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.win.freq_ts.eps"
plot data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:4 with points ls 1 title "win size=10", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:5 with points ls 2 title "win size=50", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:6 with points ls 3 title "win size=100", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:7 with points ls 4 title "win size=200"
################################
set output figure_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.ewma.freq_ts.eps"
plot data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:8 with points ls 1 title "EWMA alpha=0.1", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:9 with points ls 2 title "EWMA alpha=0.5", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq_ts.txt" using 1:10 with points ls 3 title "EWMA alpha=0.9"


########################################
reset
set terminal postscript enhanced
set size ratio 0.7
figure_dir = "./figures_freq"
data_dir = "./output_freq"
set xlabel "TIMESTAMP"
set ylabel "error of estimated time (s)"
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

################################
set output figure_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.freq.err_ts.eps"
plot data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:3 with points ls 1 title "avg"
################################
set output figure_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.win.err_ts.eps"
plot data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:4 with points ls 1 title "win size=10", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:5 with points ls 2 title "win size=50", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:6 with points ls 3 title "win size=100", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:7 with points ls 4 title "win size=200"
################################
set output figure_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.ewma.err_ts.eps"
plot data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:8 with points ls 1 title "EWMA alpha=0.1", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:9 with points ls 2 title "EWMA alpha=0.5", \
data_dir."/2013.10.14.iphone.tr1.iperf.pcap.txt.192.168.1.7.err_ts.txt" using 1:10 with points ls 3 title "EWMA alpha=0.9"