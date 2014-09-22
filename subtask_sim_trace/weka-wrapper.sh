#!/bin/bash 

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_sim_trace/detection/sim.i5.a5.w5.s1.dup1.host0.2.bt0.s1.feature.weka.arff -T ../processed_data/subtask_sim_trace/detection/sim.i5.a5.w5.s1.dup1.host0.2.bt0.s1.feature.weka.arff -i > tmp.weka.1.txt


# java weka.classifiers.trees.J48 -t ../processed_data/subtask_sim_trace/detection/sim.i100.a500.w400.s1.dup1.host0.2.bt0.s2.feature.weka.arff -T ../processed_data/subtask_sim_trace/detection/sim.i100.a500.w400.s1.dup1.host0.2.bt0.s1.feature.weka.arff -i #> tmp.weka.21.txt

# java weka.classifiers.trees.J48 -t ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s1.feature.weka.arff -T ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s1.feature.weka.arff -i

java weka.classifiers.trees.J48 -t ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s1.feature.weka.arff -T ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s2.feature.weka.arff -i

java weka.classifiers.trees.J48 -t ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s2.feature.weka.arff -T ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s1.feature.weka.arff -i


java weka.classifiers.trees.J48 -t ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt60000.s2.feature.weka.arff -T ../processed_data/subtask_sim_trace/detection/sim.i30.a30.w40.s1.dup1.host0.2.bt60000.s2.feature.weka.arff -i
