
##################
## Windows
##################
reset
set terminal postscript enhanced font "Helvetica,28"
set size ratio 0.7

set output "./figure_statistics/ip_id_windows.eps"
set xlabel "packets" font "Helvetica,28"
set ylabel "IP ID" font "Helvetica,28"
set tics font "Helvetica,20"

set key Left over reverse nobox spacing 0.5 font "Helvetica,20"
#set key right bottom font "Helvetica,20"

set xrange [0:6000]
set xtics 0,1000,6000
set xtics rotate by -90

set style line 1 lc rgb "#0000FF" lt 1 lw 5
set style line 2 lc rgb "#FF0000" lt 2 lw 5
set style line 3 lc rgb "green" lt 3 lw 3
set style line 4 lc rgb "orange" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot './output_statistics/win.dell.txt' using 1 with linespoints ls 1 title "web surfing 1", \
     './output_statistics/win.toshiba.txt' using 1 with linespoints ls 2 title "web surfing 2"

##################
## HTC
##################

set xrange [0:6000]
set xtics 0,1000,6000
set key Left over reverse nobox font "Helvetica,18"
set output "./figure_statistics/ip_id_htc.eps"
plot './output_statistics/htc.web.txt' using 1 with linespoints ls 3 title "web", \
     './output_statistics/htc.video.txt' using 1 with linespoints ls 2 title "video", \
     './output_statistics/htc.iperf.txt' using 1 with linespoints ls 1 title "iPerf"



##################
## Samsung
##################

set xrange [0:2000]
set xtics 0,200,2000
set key Left over reverse nobox font "Helvetica,18"
set output "./figure_statistics/ip_id_samsung.eps"
plot './output_statistics/samsung.web.txt' using 1 with linespoints ls 3 title "web", \
     './output_statistics/samsung.video.txt' using 1 with linespoints ls 2 title "video", \
     './output_statistics/samsung.iperf.txt' using 1 with linespoints ls 1 title "iPerf"



##################
## Apple
##################

set xrange [0:2000]
set xtics 0,200,2000
set key Left over reverse nobox spacing 1 font "Helvetica,20"
set output "./figure_statistics/ip_id_apple.eps"
plot './output_statistics/osx.txt' using 1 with linespoints ls 2 title "OS X", \
     './output_statistics/iphone.video.txt' using 1 with linespoints ls 1 title "iPhone"
     




