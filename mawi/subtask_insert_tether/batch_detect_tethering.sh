#!/bin/bash

echo "text 5, exp=0, ratio=0.01"
perl replace_ip.pl text5 0 0.01
echo "text 5, exp=1, ratio=0.001"
perl replace_ip.pl text5 1 0.001
echo "text 5, exp=2, ratio=0.02"
perl replace_ip.pl text5 2 0.02
echo "text 5, exp=3, ratio=0.03"
perl replace_ip.pl text5 3 0.03
echo "text 5, exp=4, ratio=0.04"
perl replace_ip.pl text5 4 0.04
echo "text 5, exp=5, ratio=0.05"
perl replace_ip.pl text5 5 0.05
echo "text 5, exp=6, ratio=0.06"
perl replace_ip.pl text5 6 0.06
echo "text 5, exp=7, ratio=0.1"
perl replace_ip.pl text5 7 0.1


echo "detect tethering"
perl detect_tethering.pl 201101091400.dump.txt > /dev/null
echo "detect tethering exp=0"
perl detect_tethering.pl 201101091400.dump.txt.exp0.txt > /dev/null
echo "detect tethering exp=1"
perl detect_tethering.pl 201101091400.dump.txt.exp1.txt > /dev/null
echo "detect tethering exp=2"
perl detect_tethering.pl 201101091400.dump.txt.exp2.txt > /dev/null
echo "detect tethering exp=3"
perl detect_tethering.pl 201101091400.dump.txt.exp3.txt > /dev/null
echo "detect tethering exp=4"
perl detect_tethering.pl 201101091400.dump.txt.exp4.txt > /dev/null
echo "detect tethering exp=5"
perl detect_tethering.pl 201101091400.dump.txt.exp5.txt > /dev/null
echo "detect tethering exp=6"
perl detect_tethering.pl 201101091400.dump.txt.exp6.txt > /dev/null
echo "detect tethering exp=7"
perl detect_tethering.pl 201101091400.dump.txt.exp7.txt > /dev/null


echo "compare results exp=0"
perl detect_tethering_compare_output.pl exp0.txt 201101091400.dump.txt.exp0.txt 201101091400.dump.txt > /dev/null
echo "compare results exp=1"
perl detect_tethering_compare_output.pl exp1.txt 201101091400.dump.txt.exp1.txt 201101091400.dump.txt > /dev/null
echo "compare results exp=2"
perl detect_tethering_compare_output.pl exp2.txt 201101091400.dump.txt.exp2.txt 201101091400.dump.txt > /dev/null
echo "compare results exp=3"
perl detect_tethering_compare_output.pl exp3.txt 201101091400.dump.txt.exp3.txt 201101091400.dump.txt > /dev/null
echo "compare results exp=4"
perl detect_tethering_compare_output.pl exp4.txt 201101091400.dump.txt.exp4.txt 201101091400.dump.txt > /dev/null
echo "compare results exp=5"
perl detect_tethering_compare_output.pl exp5.txt 201101091400.dump.txt.exp5.txt 201101091400.dump.txt > /dev/null
echo "compare results exp=6"
perl detect_tethering_compare_output.pl exp6.txt 201101091400.dump.txt.exp6.txt 201101091400.dump.txt > /dev/null
echo "compare results exp=7"
perl detect_tethering_compare_output.pl exp7.txt 201101091400.dump.txt.exp7.txt 201101091400.dump.txt > /dev/null


echo "compare results exp=0"
perl detect_tethering_compare_output.pl exp0.txt 201101091400.dump.txt.exp0.txt > /dev/null
echo "compare results exp=1"
perl detect_tethering_compare_output.pl exp1.txt 201101091400.dump.txt.exp1.txt > /dev/null
echo "compare results exp=2"
perl detect_tethering_compare_output.pl exp2.txt 201101091400.dump.txt.exp2.txt > /dev/null
echo "compare results exp=3"
perl detect_tethering_compare_output.pl exp3.txt 201101091400.dump.txt.exp3.txt > /dev/null
echo "compare results exp=4"
perl detect_tethering_compare_output.pl exp4.txt 201101091400.dump.txt.exp4.txt > /dev/null
echo "compare results exp=5"
perl detect_tethering_compare_output.pl exp5.txt 201101091400.dump.txt.exp5.txt > /dev/null
echo "compare results exp=6"
perl detect_tethering_compare_output.pl exp6.txt 201101091400.dump.txt.exp6.txt > /dev/null
echo "compare results exp=7"
perl detect_tethering_compare_output.pl exp7.txt 201101091400.dump.txt.exp7.txt > /dev/null

