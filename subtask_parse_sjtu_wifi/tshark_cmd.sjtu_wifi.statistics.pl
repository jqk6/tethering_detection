#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2014.04.14 @ UT Austin
##
## - input:
##   1. ip: the ip that collected the trace (the target client device)
##
## - output:
##
## - e.g.
##   perl tshark_cmd.sjtu_wifi.statistics.pl 111.0.0.0/8
##
##########################################

use strict;
use lib "../utils";

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print output


#############
# Constants
#############


#############
# Variables
#############
my $input_dir  = "/u/yichao/anomaly_compression/data/sjtu_wifi/pcap";
# my $output_dir = "../processed_data/subtask_parse_sjtu_wifi/tshark";
# my $output_file = "sjtu_wifi";
my $tmp_file = "./tmp.flows.txt";

my $ip;
my $filename;

#############
# check input
#############
if(@ARGV != 1) {
    print "wrong number of input: ".@ARGV."\n";
    print join("\n", @ARGV)."\n";
    exit;
}
$ip = $ARGV[0];

if($DEBUG2) {
    print "input:\n";
    print "  device ip: $ip\n";
    print "  input dir: $input_dir\n";
    # print "  trace file: $filename\n";
}


#############
# Main starts
#############

if(0) {
    ## clean the tmp file
    if(-e "$tmp_file") {
        `rm $tmp_file`;
    }


    ## read all files
    print "read all files\n" if($DEBUG2);
    my @files;
    opendir(my $dh, $input_dir) or die $!;
    while(readdir $dh) {
        next if(-d "$input_dir/$_");

        print "  $input_dir/$_\n" if($DEBUG0);
        push @files, $_;
    }
    closedir $dh;


    ## sort files by name
    print "sort files by name\n" if($DEBUG2);
    foreach my $cfilename (sort {$a <=> $b} (@files)) {
        my ($filename, $tmp) = split(/\./, $cfilename);
        print "  $filename:\n" if($DEBUG2);


        ## decompress
        if($cfilename =~ /\.gz$/) {
            print "  decompress pcap file\n" if($DEBUG2);
            my $cmd = "gunzip \"$input_dir/$filename.gz\"";
            `$cmd`;
        }


        ## tshark 
        print "  run tshark\n" if($DEBUG2);
        # ($frame_num, $time, $frame_len, $ip_id, $ip_src, $ip_dst, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports)

        # my $cmd = "tshark -r $input_dir/$filename -R \"ip.addr == $ip\" -T fields -E separator=\\\| -e frame.number -e frame.time_epoch -e frame.len -e ip.src -e ip.dst -e ip.id -e ip.ttl -e ip.flags.df -e ip.flags.rb -e ip.flags.sf -e ip.opt.len -e ip.opt.type.number -e ip.opt.ext_sec_add_sec_info -e ip.opt.id_number -e ip.opt.mtu -e ip.opt.ohc -e ip.opt.padding -e ip.opt.ptr -e ip.opt.qs_rate -e ip.opt.qs_ttl -e ip.opt.qs_unused -e ip.opt.sec_cl -e ip.opt.sid -e ip.dsfield.ce -e ip.dsfield.dscp -e ip.dsfield.ecn -e ip.dsfield.ect -e ip.tos.cost -e ip.tos.delay -e ip.tos.precedence -e ip.tos.reliability -e ip.tos.throughput -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e tcp.len -e tcp.option_kind -e tcp.option_len -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -e tcp.analysis.bytes_in_flight -e tcp.window_size_scalefactor -e tcp.window_size_value -e tcp.pdu.size -e tcp.continuation_to -e tcp.analysis.reused_ports -e http.user_agent > $output_dir/$filename.txt";

        my $cmd = "tshark -r \"$input_dir/$filename\" -R \"ip.src == $ip && tcp\"  -T fields -E separator=\\\| -e ip.src -e ip.dst >> $tmp_file";

        print "    > ".$cmd."\n";
        `$cmd`;


        ## compress pcap file
        print "  compress pcap file\n" if($DEBUG2);
        $cmd = "gzip \"$input_dir/$filename\"";
        `$cmd`;

    }
}


## number of packets
print "number of packets\n";
my $cmd = "cat $tmp_file | wc -l";
print `$cmd`;


## number of flows
print "number of flows\n";
my $cmd = "cat $tmp_file | sort | uniq | wc -l";
print `$cmd`;


## number of users
print "number of users\n";
my $account_dir = "/u/yichao/anomaly_compression/data/sjtu_wifi/RADIUS";
$cmd = "bzcat $account_dir/RADIUS\\ Accounting\\ 2013-01-04_anonymous.csv.bz2 $account_dir/RADIUS\\ Accounting\\ 2013-01-05_anonymous.csv.bz2 $account_dir/RADIUS\\ Accounting\\ 2013-01-06_anonymous.csv.bz2 $account_dir/RADIUS\\ Accounting\\ 2013-01-07_anonymous.csv.bz2 $account_dir/RADIUS\\ Accounting\\ 2013-01-08_anonymous.csv.bz2 $account_dir/RADIUS\\ Accounting\\ 2013-01-09_anonymous.csv.bz2 $account_dir/RADIUS\\ Accounting\\ 2013-01-10_anonymous.csv.bz2 | awk -F',' '{print \$3}'  | sort | uniq | wc -l";
print "$cmd\n";
print `$cmd`;
