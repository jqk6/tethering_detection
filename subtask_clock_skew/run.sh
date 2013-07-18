#/bin/sh

## remember to modify some parameters in calculate_clock_skew.pl individually
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.12machines.pcap.txt
perl calculate_clock_skew.pl ~/testbed/exp3/text5/2013.07.01.iphone,ipad-web.pcap.txt 
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.10.mobile_devices.1s.short.pcap.txt
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.10.mobile_devices.fc2.short.pcap.txt
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.11.HTC.iperf.2min.pcap.txt
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.11.Samsung.iperf.2min.pcap.txt
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.11.HTC.web.2min.pcap.txt
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.11.HTC.video.2min.pcap.txt

perl calculate_clock_skew_remove_delay_intermediate_sue.pl ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.intermediate_node_wired.pcap.txt ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.dest_node.pcap.txt
perl calculate_clock_skew_remove_delay_intermediate_sue.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.intermediate_node_wired.pcap.txt ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.dest_node.pcap.txt