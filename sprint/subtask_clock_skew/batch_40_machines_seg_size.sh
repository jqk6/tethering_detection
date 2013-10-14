#!/bin/bash

dir="./output"
# files=`ls $dir/2013.08.19.40utmachines.pcap.txt.128*.offset.txt`

# for f in $files ; do
#     truncate $f.seg_size.txt --size 0 
# done

# for seg in {60..1800..60} ; do
#     for f in $files ; do
#         date
#         echo "  "$f" "${seg}
#         perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f ${seg} >> $f.seg_size.txt
#     done
# done

#######################################################################

# files=`ls $dir/2013.08.20.40utmachines.pcap.txt.128*.offset.txt`

# for f in $files ; do
#     truncate $f.seg_size.txt --size 0 
# done

# for seg in {60..1800..60} ; do
#     for f in $files ; do
#         date
#         echo "  "$f" "${seg}
#         perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f ${seg} >> $f.seg_size.txt
#     done
# done

#######################################################################

# files=`ls $dir/2013.09.23.universities.short.pcap.txt.*.offset.txt`

# for f in $files ; do
#     truncate $f.seg_size.txt --size 0 
# done

# for seg in {60..1800..60} ; do
#     for f in $files ; do
#         date
#         echo "  "$f" "${seg}
#         perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f ${seg} >> $f.seg_size.txt
#     done
# done


#######################################################################

# files=`ls $dir/2013.09.23.universities.10hr.pcap.txt.*.offset.txt`

# for f in $files ; do
#     truncate $f.seg_size.txt --size 0 
# done

# for seg in {60..1800..60} ; do
#     for f in $files ; do
#         date
#         echo "  "$f" "${seg}
#         perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f ${seg} >> $f.seg_size.txt
#     done
# done

#######################################################################

files=`ls $dir/2013.09.24.universities.10hr.3.pcap.txt.*.offset.txt`

for f in $files ; do
    truncate $f.seg_size.txt --size 0 
done

for seg in {60..1800..60} ; do
    for f in $files ; do
        date
        echo "  "$f" "${seg}
        perl /export/home/ychen/sprint/subtask_clock_skew/calculate_clock_skew_sue_segment.pl $f ${seg} >> $f.seg_size.txt
    done
done

