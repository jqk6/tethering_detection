#!/bin/bash

LIBSVM_HOME="/u/yichao/bin/libsvm-3.17"
INPUT_DIR="/u/yichao/tethering_detection/git_repository/processed_data/subtask_sim_trace/detection"
TRAIN_FILE="sim.i100.a500.w400.s1.dup1.host0.3.bt86400.s1.feature.svm.txt"
TEST_FILE="sim.i100.a500.w400.s1.dup1.host0.3.bt86400.s1.feature.svm.txt"

${LIBSVM_HOME}/svm-scale -s ./tmp.range ${INPUT_DIR}/${TRAIN_FILE} > tmp.train.scale
${LIBSVM_HOME}/tools/grid.py -svmtrain ${LIBSVM_HOME}/svm-train tmp.train.scale

C=0.03125 
gamma=0.0078125

${LIBSVM_HOME}/svm-train -c ${C} -g ${gamma} tmp.train.scale tmp.train.model

${LIBSVM_HOME}/svm-scale -r tmp.range ${INPUT_DIR}/${TEST_FILE} > tmp.test.scale

${LIBSVM_HOME}/svm-predict tmp.test.scale tmp.train.model tmp.test.predict.txt