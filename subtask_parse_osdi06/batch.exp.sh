#!/bin/bash

ratio=0.3
for seed in 1 2 3 4 5; do
    echo $seed
    perl gen_trace.osdi06.pl osdi06.A.filter 1 ${ratio} 0 ${seed}
    perl statistics.osdi06.v2.pl osdi06.A.filter.dup1.host${ratio}.bt0.s${seed}
done


for training in 1 2 3 4 5; do
    for testing in 1 2 3 4 5; do
        echo "train ${training} v.s. test ${testing}"
        perl statistics.osdi06.v3.pl osdi06.A.filter.dup1.host${ratio}.bt0.s${testing} osdi06.A.filter.dup1.host${ratio}.bt0.s${training}

        echo "weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_osdi06/detection/osdi06.A.filter.dup1.host${ratio}.bt0.s${training}.weka.arff -T ../processed_data/subtask_parse_osdi06/detection/osdi06.A.filter.dup1.host${ratio}.bt0.s${testing}.weka.arff -i > ../processed_data/subtask_parse_osdi06/detection/train${training}.test${testing}.weka.txt"
        java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_osdi06/detection/osdi06.A.filter.dup1.host${ratio}.bt0.s${training}.weka.arff -T ../processed_data/subtask_parse_osdi06/detection/osdi06.A.filter.dup1.host${ratio}.bt0.s${testing}.weka.arff -i > ../processed_data/subtask_parse_osdi06/detection/train${training}.test${testing}.weka.txt
        python svm-wrapper.py ../processed_data/subtask_parse_osdi06/detection/osdi06.A.filter.dup1.host${ratio}.bt0.s${training}.svm.txt ../processed_data/subtask_parse_osdi06/detection/osdi06.A.filter.dup1.host${ratio}.bt0.s${testing}.svm.txt 
    done
done

