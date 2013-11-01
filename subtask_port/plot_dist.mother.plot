reset
# set terminal postscript eps enhanced color 28
# set terminal postscript eps enhanced monochrome 28
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
set tics font "Helvetica,24"

set xrange [X_RANGE_S:X_RANGE_E]
set yrange [Y_RANGE_S:Y_RANGE_E]

set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9

set style fill pattern 2
# set style fill solid 0.8
set palette color
# set palette gray

# set key right top
# set key Left under reverse nobox spacing 1
set nokey

# plot data_dir.file_name.".txt" \
#         using 2:xtic(1) t '{/Helvetica=28 TITLE1}', \
#      '' using 3 t '{/Helvetica=20 TITLE2}', \
#      '' using 4 t '{/Helvetica=20 TITLE3}'

plot data_dir.file_name.".txt" using 2:xtic(1) notitle
