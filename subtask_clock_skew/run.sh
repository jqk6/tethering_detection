#/bin/sh

## remember to modify some parameters in calculate_clock_skew.pl individually
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt
perl calculate_clock_skew.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.12machines.pcap.txt
perl calculate_clock_skew.pl ~/testbed/exp3/text5/2013.07.01.iphone,ipad-web.pcap.txt 