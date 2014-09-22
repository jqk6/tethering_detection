reset
set terminal postscript eps enhanced color 28
# set terminal postscript eps enhanced monochrome 28
# set terminal png enhanced 28 size 800,600
# set terminal jpeg enhanced font helvetica 28
set size ratio 0.7

data_dir = "../processed_data/subtask_plot_imc14/data/"
fig_dir  = "../processed_data/subtask_plot_imc14/figures/"
file_name = "prec0.8"
fig_name  = "prec0.8"
set output fig_dir.fig_name.".eps"

# set xlabel '{/Helvetica=28 X_LABEL}'
set ylabel '{/Helvetica=28 Recall}'

set xtics nomirror rotate by -30
set ytics nomirror
set tics font "Helvetica,28"

# set xrange [X_RANGE_S:X_RANGE_E]
set yrange [0:1]

set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9

set style fill pattern 2
# set style fill solid 0.8
set palette color
# set palette gray

# set key right top
set key at 6,1.1 horizontal samplen 1 width -1
# set key at 10,5  ## coordinate of right top corner of the legend
# set key Left under reverse horizontal spacing 0.9 samplen 1.5 width -1
# set nokey

set style line 1 lc rgb "red"     lt 1 lw 1 pt 1 ps 1.5 pi -1  ## +
set style line 2 lc rgb "blue"    lt 2 lw 1 pt 2 ps 1.5 pi -1  ## x
set style line 3 lc rgb "#00CC00" lt 1 lw 1 pt 3 ps 1.5 pi -1  ## *
set style line 4 lc rgb "#7F171F" lt 4 lw 1 pt 4 ps 1.5 pi -1  ## box
set style line 5 lc rgb "#FFD800" lt 3 lw 1 pt 5 ps 1.5 pi -1  ## solid box
set style line 6 lc rgb "#000078" lt 6 lw 1 pt 6 ps 1.5 pi -1  ## circle
set style line 7 lc rgb "#732C7B" lt 7 lw 1 pt 7 ps 1.5 pi -1
set style line 8 lc rgb "black"   lt 8 lw 1 pt 8 ps 1.5 pi -1  ## triangle
set style line 9 lc rgb "black"   lt 1 lw 1 pt 1 ps 1


set label 'max' at 0.25,0.7 right font "Helvetica,22"
bs = 0.22
plot data_dir.file_name.".testbed.txt" using 2:xtic(1) fs pattern 2 ls 1 t '{/Helvetica=24 our traces}', \
     data_dir.file_name.".testbed.txt" using ($0-bs):2:($2):($3) w yerrorbars ls 9 notitle, \
     data_dir.file_name.".osdi06.txt" using 2:xtic(1) fs pattern 3 ls 2 t '{/Helvetica=24 OSDI06}', \
     data_dir.file_name.".osdi06.txt" using ($0):2:($2):($3) w yerrorbars ls 9 notitle, \
     data_dir.file_name.".sigcomm08.txt" using 2:xtic(1) fs pattern 4 ls 3 t '{/Helvetica=24 SIGCOMM08}', \
     data_dir.file_name.".sigcomm08.txt" using ($0+bs):2:($2):($3) w yerrorbars ls 9 notitle


