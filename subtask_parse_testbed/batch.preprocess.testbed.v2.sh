#!/bin/bash

dir="/scratch/cluster/yichao/tethering_detection/processed_data/subtask_parse_testbed/tshark"
ratio=0.3
seed=1

for ex in exp1 exp2 exp3 exp4 exp5 exp6 exp7 exp8 exp9 exp10 exp11
do
    echo $ex
    # perl preprocess.testbed.v2.pl $ex
    # perl gen_trace.testbed.pl testbed.$ex.filter 1 ${ratio} 0 ${seed}
    # perl statistics.testbed.v2.pl testbed.$ex.filter.dup1.host${ratio}.bt0.s${seed} > /dev/null
done

## evaluation
# for testing in exp1 exp2 exp3 exp4 exp5 exp6 exp7 exp8 exp9 exp10 exp11
for testing in exp1 exp2 exp3 exp4 exp5 exp6 exp7 exp8 exp9 exp10 exp11
do
    training="exp1"
    echo "$training v.s. $testing"
    # perl statistics.testbed.v3.pl testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed} testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed} > /dev/null
    java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -T ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -i > ../processed_data/subtask_parse_testbed/detection/train${training}.test${testing}.weka.txt
    python svm-wrapper.py ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt 
done

training="exp2"
testing="exp3"
echo "$training v.s. $testing"
# perl statistics.testbed.v3.pl testbed.$testing.filter.dup1.host${ratio}.bt0.s${seed} testbed.$training.filter.dup1.host${ratio}.bt0.s${seed} > /dev/null
java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -T ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -i > ../processed_data/subtask_parse_testbed/detection/train${training}.test${testing}.weka.txt
python svm-wrapper.py ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt 

training="exp4"
testing="exp5"
echo "$training v.s. $testing"
# perl statistics.testbed.v3.pl testbed.$testing.filter.dup1.host${ratio}.bt0.s${seed} testbed.$training.filter.dup1.host${ratio}.bt0.s${seed} > /dev/null
java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -T ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -i > ../processed_data/subtask_parse_testbed/detection/train${training}.test${testing}.weka.txt
python svm-wrapper.py ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt 

training="exp6"
testing="exp7"
echo "$training v.s. $testing"
# perl statistics.testbed.v3.pl testbed.$testing.filter.dup1.host${ratio}.bt0.s${seed} testbed.$training.filter.dup1.host${ratio}.bt0.s${seed} > /dev/null
java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -T ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -i > ../processed_data/subtask_parse_testbed/detection/train${training}.test${testing}.weka.txt
python svm-wrapper.py ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt 

training="exp8"
testing="exp9"
echo "$training v.s. $testing"
# perl statistics.testbed.v3.pl testbed.$testing.filter.dup1.host${ratio}.bt0.s${seed} testbed.$training.filter.dup1.host${ratio}.bt0.s${seed} > /dev/null
java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -T ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -i > ../processed_data/subtask_parse_testbed/detection/train${training}.test${testing}.weka.txt
python svm-wrapper.py ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt 

training="exp10"
testing="exp11"
echo "$training v.s. $testing"
# perl statistics.testbed.v3.pl testbed.$testing.filter.dup1.host${ratio}.bt0.s${seed} testbed.$training.filter.dup1.host${ratio}.bt0.s${seed} > /dev/null
java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -T ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.weka.arff -i > ../processed_data/subtask_parse_testbed/detection/train${training}.test${testing}.weka.txt
python svm-wrapper.py ../processed_data/subtask_parse_testbed/detection/testbed.${training}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt ../processed_data/subtask_parse_testbed/detection/testbed.${testing}.filter.dup1.host${ratio}.bt0.s${seed}.svm.txt 


