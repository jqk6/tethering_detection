#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' | awk -F '.' '{print $3}'`

for itr in {0..5} ; do
    truncate output/user_agent_vs_boot_time2.$itr.txt --size 0
done

for f in $files ; do
    for itr in {0..5} ; do
        date
        echo "  "$f", "$itr
        # perl /export/home/ychen/sprint/subtask_compare/user_agent_vs_boot_time2.pl $f $itr > ./log/user_agent_vs_boot_time.$f.txt
        perl /export/home/ychen/sprint/subtask_compare/user_agent_vs_boot_time2.pl $f $itr > /dev/null
    done
done
