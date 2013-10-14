#!/bin/sh

dir="/export/home/ychen/testbed/exp2"
files=`ls $dir/pcap/*.pcap | xargs -n1 basename`
# files=`cat $dir/pcap/to_sort.txt | sort -n | awk '{print $2}'`

for f in $files ; do
   date
   echo "  "$f
   /export/home/ychen/testbed/pcapParser $dir/pcap/$f > $dir/text/$f.txt
done
