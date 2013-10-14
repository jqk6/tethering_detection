######################
## w/ and w/o TS flows
######################
reset 
set term postscript eps enhanced monochrome font "Helvetica,28"
set output "./figure_statistics/ts_w_wo_ts_flow.eps"

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
set ylabel "Ratio of flows" font "Helvetica,28"
set yrange [0:*]
set xtics rotate by 0

plot './output_statistics/ts_w_wo_ts_flow.summary.txt' using 2:xtic(1)


######################
## OS of flows w/ TS 
######################
set xtics rotate by -20
set output "./figure_statistics/ts_flow_w_ts_os.eps"
plot './output_statistics/ts_flow_w_ts_os.summary.txt' using 3:xtic(1)

######################
set xtics rotate by -20
set output "./figure_statistics/ts_flow_w_ts_os2.eps"
plot './output_statistics/ts_flow_w_ts_os.summary2.txt' using 3:xtic(1)


######################
## OS of flows w/o TS 
######################
set xtics rotate by -20
set output "./figure_statistics/ts_flow_wo_ts_os.eps"
plot './output_statistics/ts_flow_wo_ts_os.summary.txt' using 3:xtic(1)

######################
set xtics rotate by -20
set yrange [0:1]
set output "./figure_statistics/ts_flow_wo_ts_os2.eps"
plot './output_statistics/ts_flow_wo_ts_os.summary2.txt' using 3:xtic(1)



######################
## w/ and w/o TS IPs
######################
set ylabel "Ratio of IPs" font "Helvetica,28"
set xtics rotate by 0
set yrange [0:*]
set output "./figure_statistics/ts_w_wo_ts_ip.eps"
plot './output_statistics/ts_w_wo_ts_ip.summary.txt' using 2:xtic(1)


######################
## OS of IPs w/ TS 
######################
set xtics rotate by -20
set output "./figure_statistics/ts_ip_w_ts_os.eps"
plot './output_statistics/ts_ip_w_ts_os.summary.txt' using 3:xtic(1)

######################
set xtics rotate by -20
set output "./figure_statistics/ts_ip_w_ts_os2.eps"
plot './output_statistics/ts_ip_w_ts_os.summary2.txt' using 3:xtic(1)


######################
## OS of IPs w/o TS 
######################
set xtics rotate by -20
set output "./figure_statistics/ts_ip_wo_ts_os.eps"
plot './output_statistics/ts_ip_wo_ts_os.summary.txt' using 3:xtic(1)

######################
set xtics rotate by -20
set yrange [0:1]
set output "./figure_statistics/ts_ip_wo_ts_os2.eps"
plot './output_statistics/ts_ip_wo_ts_os.summary2.txt' using 3:xtic(1)

