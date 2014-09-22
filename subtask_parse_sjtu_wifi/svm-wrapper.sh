#!/bin/bash

LIBSVM_HOME="/u/yichao/bin/libsvm-3.17"
INPUT_DIR="/u/yichao/tethering_detection/git_repository/processed_data/subtask_parse_sjtu_wifi/detection"
TRAIN_FILE="sjtu_wifi.filter.dup1.host0.2.bt86400.s2.feature.svm.txt"
TEST_FILE="sjtu_wifi.filter.dup1.host0.2.bt86400.s2.feature.svm.txt"

${LIBSVM_HOME}/svm-scale -s ./tmp.range ${INPUT_DIR}/${TRAIN_FILE} > tmp.train.scale
${LIBSVM_HOME}/tools/grid.py -svmtrain ${LIBSVM_HOME}/svm-train tmp.train.scale

# C=8192.0
# gamma=0.0001220703125
C=8.0
gamma=0.0078125

${LIBSVM_HOME}/svm-train -c ${C} -g ${gamma} tmp.train.scale tmp.train.model

${LIBSVM_HOME}/svm-scale -r tmp.range ${INPUT_DIR}/${TEST_FILE} > tmp.test.scale

${LIBSVM_HOME}/svm-predict tmp.test.scale tmp.train.model tmp.test.predict.txt