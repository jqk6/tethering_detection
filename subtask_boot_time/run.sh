#!/bin/sh


## remember to modify some parameters in group_by_tcp_timestamp.pl individually
perl group_by_tcp_timestamp.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt
perl group_by_tcp_timestamp.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.12machines.pcap.txt
perl group_by_tcp_timestamp.pl ~/testbed/exp2/text5/2013.06.24.AP.pcap.txt 