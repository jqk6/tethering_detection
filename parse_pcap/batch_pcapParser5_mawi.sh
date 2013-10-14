#!/bin/sh


##########################################################
## for MAWI

dir="/data/ychen/mawi"
files=`ls $dir/pcap/*dump | xargs -n1 basename`
for f in $files ; do
   date
   echo "  "$f
   ./pcapParser5 $dir/pcap/$f > $dir/text5/$f.txt
done

