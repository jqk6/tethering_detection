#!/bin/bash

# perl tshark_cmd.pl 192.168.0.2 ../data/testbed/tcp_traces/pcap/2013.10.30.windows.youtube.pcap
# perl tshark_cmd.pl 192.168.0.2 ../data/testbed/tcp_traces/pcap/2013.10.30.windows.ie.pcap

# perl tshark_cmd.pl 192.168.0.5 ../data/testbed/tcp_traces/pcap/2013.10.30.mac.chrome.pcap
# perl tshark_cmd.pl 192.168.0.5 ../data/testbed/tcp_traces/pcap/2013.10.30.mac.youtube.pcap

dir="/u/yichao/anomaly_compression/data/sjtu_wifi/pcap/"
# for file in ${dir}*; do
# 	date
# 	echo "  "${file// /\\ }
# 	perl tshark_cmd.pl 111.18 "${file// /\\ }"
# done
perl tshark_cmd.pl 111.0.0.0/8 ${dir}sjtu_wifi_merge.pcap
# perl tshark_user_agent_cmd.pl 111.0.0.0/8 ${dir}sjtu_wifi_merge.pcap