reset
set terminal postscript eps enhanced color 28
# set terminal postscript eps enhanced monochrome 28
# set terminal png enhanced 28 size 800,600
# set terminal jpeg enhanced font helvetica 28
set size ratio 0.7

data_dir = "../processed_data/subtask_plot_imc14/data/"
fig_dir  = "../processed_data/subtask_plot_imc14/figures/"
file_name = "ttl.val.data"
fig_name  = "ttl.val.data"
set output fig_dir.fig_name.".eps"

# set xlabel '{/Helvetica=28 TTL}'
set ylabel '{/Helvetica=28 Ratio of packets}'

set xtics nomirror rotate by 0
set ytics nomirror
set tics font "Helvetica,24"

# set xrange [X_RANGE_S:X_RANGE_E]
set yrange [0:1]

set style data histogram
set style histogram cluster gap 1 title offset 0,-0.5
set style fill solid border -1
set boxwidth 0.9

set style fill pattern 2
# set style fill solid 0.8
set palette color
# set palette gray

# set key right top
# set key Left under reverse horizontal spacing 0.9 samplen 1.5 width -1
set nokey


set style line 1 lc rgb "red"     lt 1 lw 1 pt 1 ps 1.5 pi -1  ## +
set style line 2 lc rgb "blue"    lt 1 lw 1 pt 2 ps 1.5 pi -1  ## x
set style line 3 lc rgb "#00CC00" lt 1 lw 1 pt 3 ps 1.5 pi -1  ## *
set style line 4 lc rgb "#7F171F" lt 4 lw 1 pt 4 ps 1.5 pi -1  ## box
set style line 5 lc rgb "#FFD800" lt 3 lw 1 pt 5 ps 1.5 pi -1  ## solid box
set style line 6 lc rgb "#000078" lt 6 lw 1 pt 6 ps 1.5 pi -1  ## circle
set style line 7 lc rgb "#732C7B" lt 7 lw 1 pt 7 ps 1.5 pi -1
set style line 8 lc rgb "black"   lt 8 lw 1 pt 8 ps 1.5 pi -1  ## triangle


#plot data_dir.file_name.".txt" \
#     using 4:xtic(1) fs pattern 2 ls 1

plot newhistogram "our traces",\
     data_dir.file_name.".txt" using 2:xtic(1) fs pattern 2 ls 1, \
     newhistogram "OSDI06",\
     data_dir.file_name.".txt" using 4:xtic(1) fs pattern 3 ls 2, \
     newhistogram "SIGCOMM08",\
     data_dir.file_name.".txt" using 5:xtic(1) fs pattern 4 ls 3
