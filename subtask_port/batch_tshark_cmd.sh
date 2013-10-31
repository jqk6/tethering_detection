#!/bin/bash

perl tshark_cmd.pl 192.168.0.2 ../data/testbed/tcp_traces/pcap/2013.10.30.windows.youtube.pcap
perl tshark_cmd.pl 192.168.0.2 ../data/testbed/tcp_traces/pcap/2013.10.30.windows.ie.pcap

perl tshark_cmd.pl 192.168.0.5 ../data/testbed/tcp_traces/pcap/2013.10.30.mac.chrome.pcap
perl tshark_cmd.pl 192.168.0.5 ../data/testbed/tcp_traces/pcap/2013.10.30.mac.youtube.pcap
