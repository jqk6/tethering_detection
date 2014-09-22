#!/bin/bash 

for s1 in 1 2 3 4 5; do
    for s2 in 1 2 3 4 5; do
        echo $s1 "v.s." $s2
        java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s${s1}.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s${s2}.feature.weka.arff -i > tmp.weka.${s1}${s2}.txt
        cat tmp.weka.${s1}${s2}.txt | tail -13 | head -3
    done
done

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s1.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s1.feature.weka.arff -i > tmp.weka.1.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s2.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s2.feature.weka.arff -i > tmp.weka.2.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s3.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s3.feature.weka.arff -i > tmp.weka.3.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s4.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s4.feature.weka.arff -i > tmp.weka.4.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s5.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s5.feature.weka.arff -i > tmp.weka.5.txt



# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s1.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s2.feature.weka.arff -i > tmp.weka.12.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s1.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s3.feature.weka.arff -i > tmp.weka.13.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s1.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s4.feature.weka.arff -i > tmp.weka.14.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s1.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s5.feature.weka.arff -i > tmp.weka.15.txt



# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s4.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s1.feature.weka.arff -i > tmp.weka.41.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s4.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s2.feature.weka.arff -i > tmp.weka.42.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s4.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s3.feature.weka.arff -i > tmp.weka.43.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s4.feature.weka.arff -T ../processed_data/subtask_parse_sjtu_wifi/detection/sjtu_wifi.filter.dup1.host0.2.bt0.s5.feature.weka.arff -i > tmp.weka.45.txt
