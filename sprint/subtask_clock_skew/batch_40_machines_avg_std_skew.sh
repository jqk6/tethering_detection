#!/bin/bash

dir="./output"
# files=`ls $dir/2013.08.19.40utmachines.pcap.txt.128*.offset.txt`

# truncate ./output/2013.08.19.40utmachines.seg.txt --size 0 

# for f in $files ; do
#     date
#     echo "  "$f
#     perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f 600 >> ./output/2013.08.19.40utmachines.seg.txt
# done

###########################################

# truncate ./output/testbed.seg.txt --size 0 

# perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl ./output/2013.07.11.HTC.iperf.2min.pcap.txt.10.0.2.5.offset.txt 30 >> ./output/testbed.seg.txt
# perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl ./output/2013.07.11.HTC.video.2min.pcap.txt.10.0.2.5.offset.txt 30 >> ./output/testbed.seg.txt
# perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl ./output/2013.07.11.Samsung.iperf.2min.pcap.txt.10.0.2.8.offset.txt 30 >> ./output/testbed.seg.txt
# perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl ./output/2013.07.12.Samsung_iphone.fc2video_iperf.pca.txt.10.0.2.8.offset.txt 30 >> ./output/testbed.seg.txt


############################################

# files=`ls $dir/2013.08.20.40utmachines.pcap.txt.128*.offset.txt`

# truncate ./output/2013.08.20.40utmachines.seg.txt --size 0 

# for f in $files ; do
#     date
#     echo "  "$f
#     perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f 600 >> ./output/2013.08.20.40utmachines.seg.txt
# done


############################################

# files=`ls $dir/2013.09.23.universities.short.pcap.txt.*.offset.txt`

# truncate ./output/2013.09.23.universities.short.seg.txt --size 0 

# for f in $files ; do
#     date
#     echo "  "$f
#     perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f 60 >> ./output/2013.09.23.universities.short.seg.txt
# done

############################################

# files=`ls $dir/2013.09.23.universities.10hr.pcap.txt.*.offset.txt`

# truncate ./output/2013.09.23.universities.10hr.seg.txt --size 0 

# for f in $files ; do
#     date
#     echo "  "$f
#     perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f 600 >> ./output/2013.09.23.universities.10hr.seg.txt
# done

############################################

files=`ls $dir/2013.09.24.universities.10hr.3.pcap.txt.*.offset.txt`

truncate ./output/2013.09.24.universities.10hr.3.seg.txt --size 0 

for f in $files ; do
    date
    echo "  "$f
    perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f 600 >> ./output/2013.09.24.universities.10hr.3.seg.txt
done
