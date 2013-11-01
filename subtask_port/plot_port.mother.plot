reset
# set terminal postscript eps enhanced color 28
set terminal png enhanced 28 size 800,600
# set terminal jpeg enhanced font helvetica 28
set size ratio 0.7

data_dir = "../processed_data/subtask_port/analysis/"
fig_dir  = "../processed_data/subtask_port/analysis_figures/"
file_name = "FILE_NAME"
fig_name  = "FIG_NAME"
set output fig_dir.fig_name.".png"

set xlabel '{/Helvetica=28 X_LABEL}'
set ylabel '{/Helvetica=28 Y_LABEL}'

set xtics nomirror
set ytics nomirror
set xtics rotate by DEGREE

set xrange [X_RANGE_S:X_RANGE_E]
set yrange [Y_RANGE_S:Y_RANGE_E]

# set key right top
# set key Left under reverse nobox spacing 1
set nokey

set style line 1 lc rgb "red"     pt 1 ps 1.5 pi -1
set style line 2 lc rgb "blue"    pt 2 ps 1.5 pi -1
set style line 3 lc rgb "#00CC00" pt 3 ps 1.5 pi -1
set style line 4 lc rgb "#7F171F" pt 4 ps 1.5 pi -1
set style line 5 lc rgb "#FFD800" pt 5 ps 1.5 pi -1
set style line 6 lc rgb "#000078" pt 6 ps 1.5 pi -1
set style line 7 lc rgb "#732C7B" pt 7 ps 1.5 pi -1
set style line 8 lc rgb "black"   pt 8 ps 1.5 pi -1
set pointintervalbox 2  ## interval to a point

# plot data_dir.file_name.".txt" using 1:3 with lines ls 2 title '{/Helvetica=28 TITLE_1}', \
#      data_dir.file_name.".txt" using 1:2 with lines ls 1 notitle

plot data_dir.file_name.".txt" using 1:2 with points ls 1 notitle
