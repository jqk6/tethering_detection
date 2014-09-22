#!/bin/bash

for seed in 2 3 4 5; do
    echo "> seed " $seed

    perl gen_trace.sjtu_wifi.pl sjtu_wifi.filter 1 0.2 0 ${seed}
    perl detect_features.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.2.bt0.s${seed}
    perl train_prob.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.2.bt0.s${seed}
done


