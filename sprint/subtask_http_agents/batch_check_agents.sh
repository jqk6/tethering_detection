#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' `

for f in $files ; do
   date
   echo "  "$f
   perl /export/home/ychen/sprint/subtask_http_agents/check_agents.pl $dir/text3/$f.txt > ./output/$f.agents.txt
done
