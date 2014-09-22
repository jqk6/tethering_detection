#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## - input:
##   1. ip: the ip that collected the trace (the target client device)
##   2. trace_fullpath: pcap full path
##
## - output:
##
## - e.g.
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
my $input_dir  = "";
my $output_dir = "../processed_data/subtask_port/text";

my $ip;
my $trace_fullpath;
my $filename;

#############
# check input
#############
if(@ARGV != 2) {
    print "wrong number of input: ".@ARGV."\n";
    print join("\n", @ARGV)."\n";
    exit;
}
$ip = $ARGV[0];
$trace_fullpath = $ARGV[1];
if($trace_fullpath =~ /(.*)\/(.*)$/) {
    $input_dir = $1;
    $filename = $2;
}

if($DEBUG2) {
    print "device ip: $ip\n";
    print "input dir: $input_dir\n";
    print "trace file: $filename\n";
}


#############
# Main starts
#############
# ($frame_num, $time, $frame_len, $ip_id, $ip_src, $ip_dst, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports)

# tshark -r ~/Project/tethering_detection/git_repository/data/testbed/tcp_traces/pcap/2013.10.30.windows.youtube.pcap -R "ip.host == 192.168.0.2" -T fields -E separator=\| -e frame.number -e frame.time_epoch -e frame.len -e ip.id -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e tcp.len -e tcp.option_kind -e tcp.option_len -e tcp.analysis.bytes_in_flight -e tcp.window_size_scalefactor -e tcp.window_size_value -e tcp.pdu.size -e tcp.continuation_to -e tcp.analysis.reused_ports

# my $cmd = "tshark -r $trace_fullpath -R \"ip.host == $ip\" -T fields -E separator=\\\| -e frame.number -e frame.time_epoch -e frame.len -e ip.id -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e tcp.len -e tcp.option_kind -e tcp.option_len -e tcp.analysis.bytes_in_flight -e tcp.window_size_scalefactor -e tcp.window_size_value -e tcp.pdu.size -e tcp.continuation_to -e tcp.analysis.reused_ports > $output_dir/$filename.txt";

# my $cmd = "tshark -r $trace_fullpath -R \"ip.addr == $ip\" -T fields -E separator=\\\| -e frame.number -e frame.time_epoch -e frame.len -e ip.id -e ip.src -e ip.dst -e ip.flags.df -e ip.flags.rb -e ip.flags.sf -e ip.opt.len -e ip.opt.type.number -e ip.opt.ext_sec_add_sec_info -e ip.opt.id_number -e ip.opt.mtu -e ip.opt.ohc -e ip.opt.padding -e ip.opt.ptr -e ip.opt.qs_rate -e ip.opt.qs_ttl -e ip.opt.qs_unused -e ip.opt.sec_cl -e ip.opt.sid -e ip.dsfield.ce -e ip.dsfield.dscp -e ip.dsfield.ecn -e ip.dsfield.ect -e ip.tos.cost -e ip.tos.delay -e ip.tos.precedence -e ip.tos.reliability -e ip.tos.throughput -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e tcp.len -e tcp.option_kind -e tcp.option_len -e tcp.analysis.bytes_in_flight -e tcp.window_size_scalefactor -e tcp.window_size_value -e tcp.pdu.size -e tcp.continuation_to -e tcp.analysis.reused_ports > $output_dir/$filename.txt";

my $cmd = "tshark -r $trace_fullpath -R \"ip.addr == $ip\" -T fields -E separator=\\\| -e frame.number -e frame.time_epoch -e frame.len -e ip.src -e ip.dst -e ip.id -e ip.ttl -e ip.flags.df -e ip.flags.rb -e ip.flags.sf -e ip.opt.len -e ip.opt.type.number -e ip.opt.ext_sec_add_sec_info -e ip.opt.id_number -e ip.opt.mtu -e ip.opt.ohc -e ip.opt.padding -e ip.opt.ptr -e ip.opt.qs_rate -e ip.opt.qs_ttl -e ip.opt.qs_unused -e ip.opt.sec_cl -e ip.opt.sid -e ip.dsfield.ce -e ip.dsfield.dscp -e ip.dsfield.ecn -e ip.dsfield.ect -e ip.tos.cost -e ip.tos.delay -e ip.tos.precedence -e ip.tos.reliability -e ip.tos.throughput -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e tcp.len -e tcp.option_kind -e tcp.option_len -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -e tcp.analysis.bytes_in_flight -e tcp.window_size_scalefactor -e tcp.window_size_value -e tcp.pdu.size -e tcp.continuation_to -e tcp.analysis.reused_ports -e http.user_agent > $output_dir/$filename.txt";


print $cmd."\n";
`$cmd`;

## compress
$cmd = "bzip2 $output_dir/$filename.txt";
`$cmd`;

