#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' | awk -F '.' '{print $3}'`

for itr in {0..0} ; do
    truncate output_statistics/user_agent_vs_ttl_id.$itr.txt --size 0
done

for f in $files ; do
    for itr in {0..0} ; do
        date
        echo "  "$f", "$itr
        perl /export/home/ychen/sprint/subtask_compare/user_agent_vs_ttl_id.pl $f $itr > /dev/null
    done
done
