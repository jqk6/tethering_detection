#!/bin/bash

ratio=0.3
for seed in 1 2 3 4 5; do
    echo "seed $seed"
    perl gen_trace.sigcomm08.pl sigcomm08.4.filter 1 ${ratio} 0 ${seed}
    perl statistics.sigcomm08.v2.pl sigcomm08.4.filter.dup1.host${ratio}.bt0.s${seed}
done


for training in 1 2 3 4 5; do
    for testing in 1 2 3 4 5; do
        echo "train ${training} v.s. test ${testing}"
        perl statistics.sigcomm08.v3.pl sigcomm08.4.filter.dup1.host${ratio}.bt0.s${testing} sigcomm08.4.filter.dup1.host${ratio}.bt0.s${training}

        echo "weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sigcomm08/detection/sigcomm08.4.filter.dup1.host${ratio}.bt0.s${training}.weka.arff -T ../processed_data/subtask_parse_sigcomm08/detection/sigcomm08.4.filter.dup1.host${ratio}.bt0.s${testing}.weka.arff -i > ../processed_data/subtask_parse_sigcomm08/detection/train${training}.test${testing}.weka.txt"
        java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sigcomm08/detection/sigcomm08.4.filter.dup1.host${ratio}.bt0.s${training}.weka.arff -T ../processed_data/subtask_parse_sigcomm08/detection/sigcomm08.4.filter.dup1.host${ratio}.bt0.s${testing}.weka.arff -i > ../processed_data/subtask_parse_sigcomm08/detection/train${training}.test${testing}.weka.txt
        python svm-wrapper.py ../processed_data/subtask_parse_sigcomm08/detection/sigcomm08.4.filter.dup1.host${ratio}.bt0.s${training}.svm.txt ../processed_data/subtask_parse_sigcomm08/detection/sigcomm08.4.filter.dup1.host${ratio}.bt0.s${testing}.svm.txt 
    done
done

