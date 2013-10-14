######################
## OS of flows
######################
reset 
set term postscript eps enhanced monochrome font "Helvetica,28"
set output "./figure_statistics/us_flow_os.eps"

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
set xtics rotate by -20

plot './output_statistics/ua_flow_os.summary.txt' using 3:xtic(1)

##########################

set output "./figure_statistics/us_flow_os2.eps"
plot './output_statistics/ua_flow_os.summary2.txt' using 3:xtic(1)


######################
## OS of IPs
######################
set ylabel "Ratio of IPs" font "Helvetica,28"
set output "./figure_statistics/us_ip_os.eps"
plot './output_statistics/ua_ip_os.summary.txt' using 3:xtic(1)

##########################

set output "./figure_statistics/us_ip_os2.eps"
plot './output_statistics/ua_ip_os.summary2.txt' using 3:xtic(1)



######################
## device of flows
######################
set tics font "Helvetica,20"
set xtics rotate by -30
set ylabel "Ratio of flows" font "Helvetica,28"
set output "./figure_statistics/us_flow_device.eps"
plot './output_statistics/ua_flow_device.summary.txt' using 3:xtic(1)

##########################
set tics font "Helvetica,28"
set xtics rotate by -20
set output "./figure_statistics/us_flow_device2.eps"
plot './output_statistics/ua_flow_device.summary2.txt' using 3:xtic(1)


######################
## device of IPs
######################
set tics font "Helvetica,20"
set xtics rotate by -30
set ylabel "Ratio of IPs" font "Helvetica,28"
set output "./figure_statistics/us_ip_device.eps"
plot './output_statistics/ua_ip_device.summary.txt' using 3:xtic(1)

##########################
set tics font "Helvetica,28"
set xtics rotate by -20
set output "./figure_statistics/us_ip_device2.eps"
plot './output_statistics/ua_ip_device.summary2.txt' using 3:xtic(1)
