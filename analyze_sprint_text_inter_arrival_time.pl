#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/13 @ Narus 
##
## Group packets in flows, and analyze inter-arrival time.
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length>
##
## - output
##     ./output/
##     a) file.<id>.inter_arrival_time.ts.txt
##         timeseries of inter-arrival time of each flow
##
##  e.g.
##      perl analyze_sprint_text_inter_arrival_time.pl /data/ychen/sprint/text/omni.out.49.eth.pcap.txt
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
my %ip_info;        ## to store the information of each IP
                    ## $ip_info{ip_pair}{last_pkt_time}
                    ## @ip_info{ip_pair}{intervals}

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
open FH, $file_name or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len) = split(/\s+>*\s*/, $_);
    $time += 0;
    $time_usec += 0;
    $proto += 0;
    $id += 0;
    $len += 0;
    # my $ip_pair = "$dst>$src";
    my $ip_pair = "$src";
    next if($time == 0); ## used to ignore the last line in the input file
    print "t=$time.$time_usec, src=$src, dst=$dst, proto=$proto, ttl=$ttl, id=$id, len=$len\n" if($DEBUG1);



    ## update ip info
    my $new_time = $time + $time_usec / 1000000;
    if(!(exists $ip_info{$ip_pair}{last_pkt_time})) {
        ## the first time this IP pair is obervered
        $ip_info{$ip_pair}{last_pkt_time} = $new_time;
        next;
    }


    ## not the first time
    my $interval = $new_time - $ip_info{$ip_pair}{last_pkt_time};
    push(@{$ip_info{$ip_pair}{intervals}}, $interval);
    $ip_info{$ip_pair}{last_pkt_time} = $new_time;
}
close FH;

## XXX: last second info is lost


#####
## output results
print "output..\n";


## individual
open FH_ITV, "> $output_dir/file.$file_id.inter_arrival_time.ts.txt" or die $!;
foreach my $this_ip_pair (keys %ip_info) {
    
    ## inter-arrival time
    print FH_ITV $this_ip_pair.", ".scalar(@{$ip_info{$this_ip_pair}{intervals}}).", ".join(", ", @{$ip_info{$this_ip_pair}{intervals}})."\n";
}
close FH_ITV;

1;


#####
## functions
