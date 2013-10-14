#!/bin/sh

dir="/data/ychen/sprint"
#max=`ls $dir/*.pcap | awk -F . '{print $3}' | sort -n | tail -1`
files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}' | awk -F '.' '{print $3}'`

for f in $files ; do
# for f in 49 ; do

    ## frequency estimation methods
    for method in 1 2 3 ; do
        if [[ $method == 1 ]]; then
            ## WINDOW based
            declare -a param=(10 100)
        elif [[ $method == 2 ]]; then
            ## EWMA based
            declare -a param=(0.5 0.9)
        else
            declare -a param=(1)
        fi

        ## the parameters for the freq estimation methods
        for p in ${param[@]} ; do

            ## THRESHOLD_EST_RX_DIFF
            for threshold_diff in 1 5 30 120 ; do
            # for threshold_diff in 1 ; do

                ## OUT_RANGE_NUM
                for threshold_num in 1 5 10 ; do
                # for threshold_num in 1 ; do
                    date
                    echo "  "$f", method="$method", parameter="$p", threshold_diff="$threshold_diff", threshold_num="$threshold_num

                    perl /export/home/ychen/sprint/detect_tethering_boot_time.pl $f $method $p $threshold_diff $threshold_num
                done
            done
        done
    done

done
