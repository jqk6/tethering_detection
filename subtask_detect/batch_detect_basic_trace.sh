#!/bin/bash

## 31mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.11.HTC.iperf.2min.pcap.txt "src" "10.0.2.5|10.0.2.1"
## 3mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.11.HTC.video.2min.pcap.txt "src" "10.0.2.5"
## 5mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.11.HTC.web.2min.pcap.txt "src" "10.0.2.5"
## 50mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.11.Samsung.iperf.2min.pcap.txt "src" "10.0.2.8|10.0.2.1"
## 1mb
# perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.iPhone.facebook.pcap.txt "src" "10.0.2.4"
## 2mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.iPhone.fc2video.pcap.txt "src" "10.0.2.4"
## 72mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt "src" "10.0.2.8|10.0.2.1"
## 2.5mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.web_video.pcap.txt "src" "10.0.2.7|10.0.2.8"
## 1mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.Samsung_iphone.web_youtube.pcap.txt "src" "10.0.2.7"
## 50mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_again.pcap.txt "src" "10.0.2.8|10.0.2.1"
## 30mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_client.pcap.txt "src" "10.0.2.8|10.0.2.1"
## 50mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.12.Samsung.iperf_dual.pcap.txt "src" "10.0.2.8|10.0.2.1"
## 1mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.15.Samsung.facebook.pcap.txt "src" "10.0.2.8"
## 20mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf_client.pcap.txt "src" "10.0.2.8"

## 45mb
perl detect_tethering.pl ../data/testbed/tcp_traces/text5/2013.07.17.iPhone.iperf_client.dest_node.pcap.txt "src" "192.168.4.78|192.168.5.67"

