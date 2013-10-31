#!/bin/bash

output_path="../processed_data/subtask_detect/output/"
path="../data/artificial/text5/"
exp=0
files=`ls -d -1 ${path}exp${exp}*.*`
perl detect_tethering_multifiles.pl $files > ${output_path}exp${exp}.txt
