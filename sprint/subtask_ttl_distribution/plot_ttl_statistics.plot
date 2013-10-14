######################
## TCP dist
######################
reset 
set term postscript eps enhanced monochrome font "Helvetica,28"
set output "./figure_statistics/ttl_tcp_dist.eps"

set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9

set style fill pattern 2
set palette gray

#set key horizontal height 5 spacing 1.7
#set key noinvert reverse Left outside box spacing 2
#set key invert box
#set key Left under reverse nobox spacing 3
set nokey


set tics font "Helvetica,28"
set xlabel "TTL" font "Helvetica,28"
set ylabel "Ratio of flows" font "Helvetica,28"
# set yrange [0:1]
set xtics rotate by -45

plot './output_statistics/tcp_ttl_dist.summary.txt' using 3:xtic(1)

#######################
set xtics rotate by 0
set output "./figure_statistics/ttl_tcp_dist2.eps"
plot './output_statistics/tcp_ttl_dist.summary2.txt' using 3:xtic(1)


######################
## TCP TTL per flow
######################

set xlabel "# TTL" font "Helvetica,28"
set ylabel "Ratio of flows" font "Helvetica,28"
set output "./figure_statistics/ttl_tcp_num_per_flow.eps"
plot './output_statistics/tcp_ttl_per_flow.summary.txt' using 3:xtic(1)


######################
## TCP TTL per ip
######################

set xlabel "# TTL" font "Helvetica,28"
set ylabel "Ratio of IPs" font "Helvetica,28"
set output "./figure_statistics/ttl_tcp_num_per_ip.eps"
plot './output_statistics/tcp_ttl_per_ip.summary.txt' using 3:xtic(1)

#######################
set output "./figure_statistics/ttl_tcp_num_per_ip2.eps"
set yrange [0:1.2]
plot './output_statistics/tcp_ttl_per_ip.summary2.txt' using 3:xtic(1), \
     ''                                                using 0:3:3 with labels center offset 0,1 notitle



######################
## UDP dist
######################
set xlabel "TTL" font "Helvetica,28"
set ylabel "Ratio of flows" font "Helvetica,28"
set yrange [*:*]
set tics font "Helvetica,18"
set xtics rotate by -90
set output "./figure_statistics/ttl_udp_dist.eps"
plot './output_statistics/udp_ttl_dist.summary.txt' using 3:xtic(1)

#######################
set tics font "Helvetica,28"
set xtics rotate by 0
set output "./figure_statistics/ttl_udp_dist2.eps"
plot './output_statistics/udp_ttl_dist.summary2.txt' using 3:xtic(1)


######################
## UDP TTL per flow
######################

set xlabel "# TTL" font "Helvetica,28"
set ylabel "Ratio of flows" font "Helvetica,28"
set output "./figure_statistics/ttl_udp_num_per_flow.eps"
plot './output_statistics/udp_ttl_per_flow.summary.txt' using 3:xtic(1)


######################
## UDP TTL per ip
######################

set xlabel "# TTL" font "Helvetica,28"
set ylabel "Ratio of IPs" font "Helvetica,28"
set output "./figure_statistics/ttl_udp_num_per_ip.eps"
plot './output_statistics/udp_ttl_per_ip.summary.txt' using 3:xtic(1)

#######################
set output "./figure_statistics/ttl_udp_num_per_ip2.eps"
set yrange [0:1.2]
plot './output_statistics/udp_ttl_per_ip.summary2.txt' using 3:xtic(1), \
     ''                                                using 0:3:3 with labels center offset 0,1 notitle



########################
## CDF
########################

######################
## TCP TTL per flow
######################
reset
set terminal postscript enhanced font "Helvetica,28"
set size ratio 0.7

set output "./figure_statistics/ttl_tcp_num_per_flow3.eps"
set xlabel "# TTL" font "Helvetica,28"
set ylabel "CDF" font "Helvetica,28"
set tics font "Helvetica,28"
set xtics 1,1,5
set nokey

set style line 1 lc rgb "#0000FF" lt 1 lw 5
set style line 2 lc rgb "#FF0000" lt 1 lw 5
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot './output_statistics/tcp_ttl_per_flow.summary3.txt' using 1:3 with linespoints ls 1


######################
## TCP TTL per ip
######################

set output "./figure_statistics/ttl_tcp_num_per_ip3.eps"
plot './output_statistics/tcp_ttl_per_ip.summary3.txt' using 1:3 with linespoints ls 1


######################
## UDP TTL per flow
######################

set output "./figure_statistics/ttl_udp_num_per_flow3.eps"
plot './output_statistics/udp_ttl_per_flow.summary3.txt' using 1:3 with linespoints ls 1


######################
## UDP TTL per ip
######################

set xtics 1,1,5
set xrange [1:5]
set output "./figure_statistics/ttl_udp_num_per_ip3.eps"
plot './output_statistics/udp_ttl_per_ip.summary3.txt' using 1:3 with linespoints ls 1


