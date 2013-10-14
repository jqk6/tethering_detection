reset 
set term postscript eps enhanced monochrome font "Helvetica,28"
set size ratio 0.7
set output "./figures/2013.08.19.40utmachines.seg.eps"

set style data histogram
set style histogram errorbars
#set style histogram cluster gap 1
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
set xlabel "machine" font "Helvetica,28"
set ylabel "clock skew (ppm)" font "Helvetica,28"
#set yrange [0:*]
set xrange [0:39]
#set xtics 1,5,39
set xtics rotate by 0

plot './output/2013.08.19.40utmachines.seg.txt'  
