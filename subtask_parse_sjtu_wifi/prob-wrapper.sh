#/bin/bash

for s1 in 1 2 3 4 5; do
    for s2 in 1 2 3 4 5; do
        echo $s1 "v.s." $s2
        # perl detect_prob.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.2.bt0.s${s2} sjtu_wifi.filter.dup1.host0.2.bt0.s${s1} > tmp.prob.${s1}${s2}.txt
        cat tmp.prob.${s1}${s2}.txt | tail -1
        
        # perl detect_prob.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.2.bt0.s${s2} sjtu_wifi.filter.dup1.host0.2.bt0.s${s1} > tmp.prob.txt
        # cat tmp.prob.txt | tail -1
    done
done

# rm tmp.prob.txt

# perl detect_prob.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.2.bt0.s4 sjtu_wifi.filter.dup1.host0.2.bt0.s1