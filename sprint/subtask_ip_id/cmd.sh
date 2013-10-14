#/bin/bash

# cat ~/data_dir/testbed/exp2/text2/2013.06.24.laptop.toshiba.pcap.txt | grep "192.168.19.3 >" | awk '{print $8}' > win.toshiba.txt

# cat ~/data_dir/testbed/exp2/text2/2013.06.24.laptop.dell.pcap.txt | grep "192.168.19.2 >" | awk '{print $8}' > win.dell.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.08.ut.12machines.pcap.txt | grep "192.168.4.82 >" | awk '{print $8}' > osx.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.11.HTC.iperf.2min.pcap.txt | grep "10.0.2.5 >" | awk '{print $8}' > htc.iperf.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.11.HTC.video.2min.pcap.txt  | grep "10.0.2.5 >" | awk '{print $8}' > htc.video.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.11.HTC.web.2min.pcap.txt  | grep "10.0.2.5 >" | awk '{print $8}' > htc.web.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.12.iPhone.fc2video.pcap.txt  | grep "10.0.2.4 >" | awk '{print $8}' > iphone.video.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.17.iPhone.iperf_client.intermediate_node_wireless.pcap.txt  | grep "10.0.2.4 >" | awk '{print $8}' > iphone.iperf.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.15.Samsung.iperf.2nd_trace.intermediate_node_wireless.pcap.txt  | grep "10.0.2.8 >" | awk '{print $8}' > samsung.iperf.txt

cat ~/data_dir/testbed/tcp_traces/text2/2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt  | grep "10.0.2.8 >" | awk '{print $8}' > samsung.video.txt

# cat ~/data_dir/testbed/tcp_traces/text2/2013.07.12.Samsung_iphone.web_youtube.pcap.txt | grep "10.0.2.8 >" | awk '{print $8}' > samsung.web.txt
