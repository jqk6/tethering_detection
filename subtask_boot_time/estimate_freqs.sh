#!/bin/sh

perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt 200
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.12machines.pcap.txt 2000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.11.HTC.iperf.2min.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.11.HTC.video.2min.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.11.HTC.web.2min.pcap.txt 2500
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.11.Samsung.iperf.2min.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.iPhone.facebook.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.iPhone.fc2video.pcap.txt 2000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.fc2video_iperf.pca.txt 2000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.web_video.pcap.txt 2000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.web_youtube.pcap.txt 500 
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_again.pcap.txt 2000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_client.pcap.txt 2000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_dual.pcap.txt 2000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.facebook.pcap.txt 500
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf_client.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.dest_node.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.intermediate_node_wired.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.intermediate_node_wireless.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.dest_node.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.intermediate_node.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.dest_node.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.intermediate_node_wired.pcap.txt 1000
perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.intermediate_node_wireless.pcap.txt 1000

