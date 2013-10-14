#!/bin/sh

perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.12machines.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.11.HTC.iperf.2min.pcap.txt 
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.11.Samsung.iperf.2min.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.12.iPhone.fc2video.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.fc2video_iperf.pca.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.web_video.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_client.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_dual.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.facebook.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf_client.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.intermediate_node_wireless.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.intermediate_node_wireless.pcap.txt

perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.intermediate_node_wired.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.dest_node.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.intermediate_node.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.dest_node.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.intermediate_node_wired.pcap.txt
perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.dest_node.pcap.txt
