#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/24 @ Narus 
##
## Analyze # connections of UDP (i.e. <src ip> <src port> <dst ip> <dst port>) of different time bins
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <udp len>
##
## - output
##     ./output/
##     a) file.<id>.udp_connections.bin<time bin size>.txt: 
##         timeseries of # of connections
##
##  e.g.
##      perl analyze_sprint_ucp_connections.pl /data/ychen/sprint/text4/omni.out.49.eth.pcap.txt
##################################################

use strict;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug


#####
## variables
my $output_dir = "./output";

my $file_name;
my $file_id;

my %ip_info;        ## ip pair seq and ack info
                    ## {time bin size}{time}{src_ip:src_port:dst_ip:dst_port}
my @timebins = (1, 5, 10, 60, 600); ## the time bin size we want to analyze


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
print "input file = $file_name\n" if($DEBUG1);
my @dir_structure = split(/\//, $file_name);
$file_id = $1+0 if(pop(@dir_structure) =~ /(\d+)/);
print "file id: $file_id\n" if($DEBUG1);


#####
## main starts here
print STDERR "start to read data..\n" if($DEBUG2);
open FH, "$file_name" or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <udp pkt len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $udp_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $udp_len += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $udp_len))."\n" if($DEBUG1);


    foreach my $this_timebin (@timebins) {
        my $this_timebin_time = int (($time + $time_usec / 1000000) / $this_timebin);
        print join(", ", ($this_timebin, ($time + $time_usec / 1000000), $this_timebin_time))."\n" if($DEBUG1);

        $ip_info{$this_timebin}{$src}{$this_timebin_time}{"$src:$s_port:$dst:$d_port"} = 1;
    }

}
close FH;


#####
## Output
print STDERR "start to print result..\n" if($DEBUG2);
foreach my $this_timebin (@timebins) {
    open FH, "> $output_dir/file.$file_id.udp_connections.bin$this_timebin.txt" or die $!;
    foreach my $this_src ( keys %{ $ip_info{$this_timebin} } ) {
        print FH "$this_src, ";

        foreach my $this_time (sort {$a <=> $b} (keys %{ $ip_info{$this_timebin}{$this_src} })) {
            print FH "".scalar(keys %{ $ip_info{$this_timebin}{$this_src}{$this_time} }).", ";
        }
        print FH "\n";
    }
    close FH;
}

