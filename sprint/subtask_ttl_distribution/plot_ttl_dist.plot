########################################################
## a) Check the distribution of TTL values.

reset
set terminal postscript enhanced
set size ratio 0.7

input_dir = "~/sprint/subtask_ttl_distribution/output/"
# file_name = "FILE_NAME"
set output input_dir."ttl_dist.eps"

set title "distribution of TTLs"
set xlabel "TTL"
set ytics nomirror
set ylabel "# of devices having this TTL"
# set key right bottom
# set key Left under reverse nobox spacing 1
set key Left above reverse nobox spacing 1
# set nokey

set style line 1 lc rgb "#FF0000" lt 1 lw 3
set style line 2 lc rgb "#0000FF" lt 1 lw 3
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot input_dir."ttl_all_dist.txt" using 1:2 with linespoints ls 1 title "all TTLs", \
     input_dir."ttl_normal_dist.txt" using 1:2 with linespoints ls 2 title "normal TTLs", \
     input_dir."ttl_tether_dist.txt" using 1:2 with linespoints ls 3 title "tether TTLs"


########################################################
## b) Check if the TTLs behind a mobile station only differs by 1.

reset
set terminal postscript enhanced
set size ratio 0.7

input_dir = "~/sprint/subtask_ttl_distribution/output/"
# file_name = "FILE_NAME"
set output input_dir."ttl_diff.eps"

set title "diff of tether TTLs"
set xlabel "TTL diff"
set ytics nomirror
set ylabel "# of devices"
# set key right bottom
# set key Left under reverse nobox spacing 1
# set key Left above reverse nobox spacing 1
set nokey

set style line 1 lc rgb "#FF0000" lt 1 lw 3
set style line 2 lc rgb "#0000FF" lt 1 lw 3
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3

plot input_dir."ttl_diff.txt" using 1:2 with linespoints ls 1

