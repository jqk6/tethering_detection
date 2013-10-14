reset
set term pngcairo
set size ratio 0.7
figure_dir = "./figures"
data_dir = "./output"
set output figure_dir."/2013.09.24.universities.10hr.3.pap.txt.png"
set xlabel "time (seconds)"
set ylabel "offset"
set nokey
set style line 1 lc rgb "#0000FF" lt 1 lw 3
set style line 2 lc rgb "#FF0000" lt 1 lw 5
set style line 3 lc rgb "orange" lt 1 lw 3
set style line 4 lc rgb "green" lt 1 lw 3
set style line 5 lc rgb "yellow" lt 1 lw 3
set style line 6 lc rgb "black" lt 1 lw 3
plot data_dir."/2013.09.24.universities.10hr.3.pap.txt.59.106.161.29.offset.txt" using 3:6 with points ls 1 title "59.106.161.29", \
-0.000102491234278484*x - 0.00254735974937882 ls 2 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.128.122.119.202.offset.txt" using 3:6 with points ls 3 title "128.122.119.202", \
-0.000102624416121391*x - 0.0716916086964865 ls 4 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.162.105.131.113.offset.txt" using 3:6 with points ls 5 title "162.105.131.113", \
-0.000238314090228815*x - 0.000449502214289045 ls 6 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.141.211.13.226.offset.txt" using 3:6 with points ls 1 title "141.211.13.226", \
0.0105563887889622*x - -0.00852241920000751 ls 2 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.128.95.155.198.offset.txt" using 3:6 with points ls 3 title "128.95.155.198", \
-0.000102458317175836*x - 0.000777850476629241 ls 4 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.128.174.180.122.offset.txt" using 3:6 with points ls 5 title "128.174.180.122", \
-0.000102495576047211*x - 0.000608299835058725 ls 6 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.23.200.70.151.offset.txt" using 3:6 with points ls 1 title "23.200.70.151", \
-0.000102467150174387*x - 0.00158674216058359 ls 2 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.198.101.129.15.offset.txt" using 3:6 with points ls 3 title "198.101.129.15", \
-0.000105094987979561*x - 0.0294422069457534 ls 4 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.128.138.129.98.offset.txt" using 3:6 with points ls 5 title "128.138.129.98", \
-0.000102406121499339*x - 0.00239053006764421 ls 6 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.70.97.96.63.offset.txt" using 3:6 with points ls 1 title "70.97.96.63", \
-0.000102357216333061*x - 0.00804667879039369 ls 2 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.169.229.216.200.offset.txt" using 3:6 with points ls 3 title "169.229.216.200", \
-0.000503333924426851*x - 0.00759156425650856 ls 4 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.131.111.150.25.offset.txt" using 3:6 with points ls 5 title "131.111.150.25", \
-0.000102380399847578*x - 0.0152883973337831 ls 6 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.129.206.13.27.offset.txt" using 3:6 with points ls 1 title "129.206.13.27", \
-0.000254467389885279*x - 0.00772101409558817 ls 2 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.140.112.30.32.offset.txt" using 3:6 with points ls 3 title "140.112.30.32", \
-0.00010277717325569*x - 0.00770179493531033 ls 4 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.171.67.215.200.offset.txt" using 3:6 with points ls 5 title "171.67.215.200", \
-0.000102376952078353*x - 0.858766190916502 ls 6 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.222.122.39.176.offset.txt" using 3:6 with points ls 1 title "222.122.39.176", \
-0.000142286038038872*x - 0.164873101055583 ls 2 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.128.97.27.37.offset.txt" using 3:6 with points ls 3 title "128.97.27.37", \
-0.000102469415685699*x - 0.00257526920003806 ls 4 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.129.78.5.11.offset.txt" using 3:6 with points ls 5 title "129.78.5.11", \
-0.000102485132246463*x - 0.00141878022101145 ls 6 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.134.84.119.107.offset.txt" using 3:6 with points ls 1 title "134.84.119.107", \
-0.000105929611965872*x - 0.0074628219774853 ls 2 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.128.83.120.139.offset.txt" using 3:6 with points ls 3 title "128.83.120.139", \
-0.000102505718747811*x - 0.00290260364812 ls 4 notitle, \
data_dir."/2013.09.24.universities.10hr.3.pap.txt.163.1.60.42.offset.txt" using 3:6 with points ls 5 title "163.1.60.42", \
-6.73852572575013e-05*x - 0.0142899214472261 ls 6 notitle