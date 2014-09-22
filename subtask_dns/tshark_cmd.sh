#!/bin/bash

input_dir="../data/testbed/tcp_traces/pcap"
output_dir="../processed_data/subtask_dns/dns_trace"

# cnt=1
# ls ${input_dir} | while read f ; do
#     echo "${cnt}: ${input_dir}$f"
#     let cnt=${cnt}+1
# done
# "dns6.pcap" "dns5.pcap" "dns4.pcap" "dns3.pcap" "dns1.pcap" "dns2.pcap"
for f in "dns.youtube.txt"; do
    echo "$input_dir/$f"
    tshark -r "$input_dir/$f" -R "dns && dns.qry.class==1" -T fields -e frame.time_relative -e ip.src -e ip.dst -e dns.id -e dns.flags.response -e dns.qry.type -e dns.qry.name -e dns.resp.ttl -E separator=\| > "${output_dir}/$f.txt"
done
# tshark -r 2013.10.30.windows.ie.pcap -R "dns && ip.src==192.168.0.2" | awk '{print $1"|"$2"|"$10"|"$11}'  > dns.windows.ie.txt