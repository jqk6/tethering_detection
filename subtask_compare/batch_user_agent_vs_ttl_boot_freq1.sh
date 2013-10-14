#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' | awk -F '.' '{print $3}'`

for itr in {0..4} ; do
    truncate output/user_agent_vs_ttl_boot_freq1.$itr.txt --size 0
done

for f in $files ; do
    for itr in {0..4} ; do
        date
        echo "  "$f", "$itr
        perl /export/home/ychen/sprint/subtask_compare/user_agent_vs_ttl_boot_freq1.pl $f $itr > /dev/null
    done
done
