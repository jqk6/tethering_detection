#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' | awk -F '.' '{print $3}'`

for itr in {0..1} ; do
    truncate output_analysis/user_agent_vs_boot_time_analysis_tethering.$itr.txt --size 0
    truncate output_analysis/user_agent_vs_boot_time_analysis_untethering.$itr.txt --size 0
done

for f in $files ; do
    for itr in {0..1} ; do
        date
        echo "  "$f", "$itr
        perl /export/home/ychen/sprint/subtask_compare/user_agent_vs_boot_time_analysis.pl $f $itr > /dev/null
    done
done
