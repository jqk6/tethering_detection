#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}'`

for f in $files ; do
   date
   echo "  "$f
   perl /export/home/ychen/sprint/analyze_sprint_http_user_agents.pl $dir/text3/$f.txt > /dev/null
done
