#!/bin/sh

# dir="/export/home/ychen/testbed/exp2"
# files=`ls $dir/pcap/*.pcap | xargs -n1 basename`
# for f in $files ; do
#    date
#    echo "  "$f
#    /export/home/ychen/testbed/pcapParser2 $dir/pcap/$f > $dir/text2/$f.txt
# done


##########################################################


# dir="/data/ychen/testbed/tcp_traces"
# files=`ls $dir/pcap/*.pcap | xargs -n1 basename`
# for f in $files ; do
#    date
#    echo "  "$f
#    /export/home/ychen/testbed/pcapParser2 $dir/pcap/$f > $dir/text2/$f.txt
# done


##########################################################

## for partitioned 2013.09.24.universities.10hr.3* traces
dir="/data/ychen/testbed/tcp_traces"
files=`ls $dir/pcap/2013.09.24.universities.10hr.3*.pcap | xargs -n1 basename`
for f in $files ; do
   date
   echo "  "$f
   /export/home/ychen/testbed/pcapParser2 $dir/pcap/$f >> $dir/text2/2013.09.24.universities.10hr.3.pcap.txt
done

