#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' | awk -F '.' '{print $3}'`

for f in $files ; do
   date
   echo "  "$f
   perl /export/home/ychen/sprint/cross_validate_detected_ip.pl $f > /dev/null
done
