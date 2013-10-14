#!/bin/bash

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}'`

file_output="./output/tcp_timestamp.txt"
rm $file_output

for f in $files ; do
   date
   echo "  "$f
   /export/home/ychen/sprint/subtask_tcp_timestamp/find_tcp_timestamp $dir/pcap/$f >> $file_output
done
