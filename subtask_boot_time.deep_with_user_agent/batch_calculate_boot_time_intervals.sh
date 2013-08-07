#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' | awk -F '.' '{print $3}'`

truncate output_boot_time_interval/intervals.txt --size 0

for f in $files ; do
   date
   echo "  "$f
   perl /export/home/ychen/sprint/subtask_boot_time.deep_with_user_agent/calculate_boot_time_intervals.pl $f > /dev/null
done
