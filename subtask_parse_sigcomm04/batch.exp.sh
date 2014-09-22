#!/bin/bash

ratio=0.3
filename="chihuahuan-ath2.03"
for seed in 1 2 3 4 5; do
    echo "seed ${seed}"
    # perl gen_trace.sigcomm04.pl ${filename}.filter 1 ${ratio} 0 ${seed}
    # perl statistics.sigcomm04.v2.pl ${filename}.filter.dup1.host${ratio}.bt0.s${seed}
done


for training in 1 2 3 4 5; do
    for testing in 1 2 3 4 5; do
        echo "train ${training} v.s. test ${testing}"
        perl statistics.sigcomm04.v3.pl ${filename}.filter.dup1.host${ratio}.bt0.s${testing} ${filename}.filter.dup1.host${ratio}.bt0.s${training}

        # echo "weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sigcomm04/detection/${filename}.filter.dup1.host${ratio}.bt0.s${training}.weka.arff -T ../processed_data/subtask_parse_sigcomm04/detection/${filename}.filter.dup1.host${ratio}.bt0.s${testing}.weka.arff -i > ../processed_data/subtask_parse_sigcomm04/detection/train${training}.test${testing}.weka.txt"
        # java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sigcomm04/detection/${filename}.filter.dup1.host${ratio}.bt0.s${training}.weka.arff -T ../processed_data/subtask_parse_sigcomm04/detection/${filename}.filter.dup1.host${ratio}.bt0.s${testing}.weka.arff -i > ../processed_data/subtask_parse_sigcomm04/detection/train${training}.test${testing}.weka.txt
        # python svm-wrapper.py ../processed_data/subtask_parse_sigcomm04/detection/${filename}.filter.dup1.host${ratio}.bt0.s${training}.svm.txt ../processed_data/subtask_parse_sigcomm04/detection/${filename}.filter.dup1.host${ratio}.bt0.s${testing}.svm.txt 
    done
done

