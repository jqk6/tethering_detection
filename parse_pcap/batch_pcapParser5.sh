#!/bin/sh


##########################################################
## for partitioned 2013.09.24.universities.10hr.3* traces

dir="/data/ychen/testbed/tcp_traces"
files=`ls $dir/pcap/2013.09.24.universities.10hr.3*.pcap | xargs -n1 basename`
for f in $files ; do
   date
   echo "  "$f
   /export/home/ychen/testbed/subtask_tcp_timestamp/find_tcp_timestamp $dir/pcap/$f >> $dir/text5/2013.09.24.universities.10hr.3.pcap.txt
done

