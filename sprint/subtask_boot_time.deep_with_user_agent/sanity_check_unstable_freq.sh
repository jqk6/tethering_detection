#!/bin/bash
#tshark -r ~/data_dir/sprint/pcap/omni.out.49.eth.pcap -R "ip.src == 28.223.196.124 && ip.dst == 74.125.224.200"  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.options.timestamp.tsval -e http.user_agent -e tcp.analysis.ack_rtt -T fields -E separator=, -E header=y > tmp.unstable1.txt
#tshark -r ~/data_dir/sprint/pcap/omni.out.49.eth.pcap -R "ip.src == 28.223.229.171 && ip.dst == 74.125.224.208"  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.options.timestamp.tsval -e http.user_agent -e tcp.analysis.ack_rtt -T fields -E separator=, -E header=y > tmp.unstable2.txt
echo "3rd"
tshark -r ~/data_dir/sprint/pcap/omni.out.49.eth.pcap -R "ip.src == 28.253.76.147 && ip.dst == 66.147.244.157"  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.options.timestamp.tsval -e http.user_agent -e tcp.analysis.ack_rtt -T fields -E separator=, -E header=y > tmp.unstable3.txt
echo "4th"
tshark -r ~/data_dir/sprint/pcap/omni.out.49.eth.pcap -R "ip.src == 28.253.76.147 && ip.dst == 66.147.244.157 && tcp.srcport == 50156"  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.options.timestamp.tsval -e http.user_agent -e tcp.analysis.ack_rtt -T fields -E separator=, -E header=y > tmp.unstable4.txt
echo "5th"
tshark -r ~/data_dir/sprint/pcap/omni.out.49.eth.pcap -R "ip.src == 28.253.76.147 && ip.dst == 66.147.244.157 && tcp.srcport == 50170"  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.options.timestamp.tsval -e http.user_agent -e tcp.analysis.ack_rtt -T fields -E separator=, -E header=y > tmp.unstable5.txt

