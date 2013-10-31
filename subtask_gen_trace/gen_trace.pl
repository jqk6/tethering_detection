#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.10.22 @ UT Austin
##
## - input: 
##   1. file_name
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##   2. exp: experiment number
##   3. trace: trace number
##   4. discard: discard the first X second data
##   5. ip_map_from
##   6. ip_map_to
##       map the srouce IP from "ip_map_from" to "ip_map_to"
##   7. ip_shift
##       shift the receiving time of the first packet to this number
##
##  e.g.
##    perl gen_trace.pl ../data/testbed/tcp_traces/text5/2013.07.11.HTC.iperf.2min.pcap.txt 1 1 0 10.0.2.5 1.1.1.1 0
##
##########################################

use lib "../utils";

use strict;
use Tethering;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 0;
my $DEBUG2 = 1;     ## program flow
my $DEBUG3 = 1;     ## results
my $DEBUG4 = 0;     ## each heuristic


#############
# Constants
#############
my $MIN_NUM_PKTS = 0;


#############
# Variables
#############
my $output_dir = "../data/artificial/text5";

my $file_name;
my $file_dir;
my $discard;
my $exp;
my $trace;
my %ip_map = ();

# my $FIX_DST      = 0;               ## 1 to fix the TCP dst
# my $FIX_DST_ADDR = "192.168.5.67";
my $FIX_SRC = 1;               ## 1 to fix the TCP src
my $FIX_SRC_ADDR = -1;

my %ip_info = ();


#############
# check input
#############
print "check input\n" if($DEBUG2);
# if(@ARGV != 1) {
#     print "wrong number of input\n";
#     exit;
# }
if($ARGV[0] =~ /(.*)\/(.*)/) {
    $file_name = $2;
    $file_dir  = $1;
}
print "  - file: $file_dir/$file_name\n" if($DEBUG2);

$exp = $ARGV[1] + 0;
print "  - exp: $exp\n" if($DEBUG2);
$trace = $ARGV[2] + 0;
print "  - trace: $trace\n" if($DEBUG2);
$discard = $ARGV[3] + 0;
print "  - discard: $discard\n" if($DEBUG2);

for (my $i = 4; $i < @ARGV; $i += 3) {
    $ip_map{$ARGV[$i]}{TO} = $ARGV[$i+1];
    $ip_map{$ARGV[$i]}{SHIFT_TO} = $ARGV[$i+2] + 0;
    if($FIX_SRC_ADDR == -1) {
        $FIX_SRC_ADDR = $ARGV[$i];
    }
    else {
        $FIX_SRC_ADDR .= "|".$ARGV[$i];
    }
    print "  - map: from ".$ARGV[$i]." to ".$ip_map{$ARGV[$i]}{TO}.", shift to ".$ip_map{$ARGV[$i]}{SHIFT_TO}."sec\n" if($DEBUG2);
}
print "  - src: $FIX_SRC_ADDR\n" if($DEBUG2);
# exit;


#############
# Main starts
#############
#############
## Read the file
#############
## TCP Timestamp
print "Start to read TCP Timestamp data\n" if($DEBUG2);
open FH, "$file_dir/$file_name" or die $!."\n$file_dir/$file_name\n";
open FH_OUT, "> $output_dir/exp$exp.tr$trace.$file_name.dis$discard.txt" or die $!."\n$output_dir/$file_name\n";
my $first_rx_time = -1;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);

    ## convert string to numbers
    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;


    next if($FIX_SRC and (!($src =~ /$FIX_SRC_ADDR/ )));
    # next if($FIX_DST and (!($dst =~ /$FIX_DST_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG0);


    ## check if it's a reordering / retransmission
    next if(exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ} and $seq < $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}[-1]);
    ## check if it's a duplicate
    next if(exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME} and 
        $tcp_ts_val == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME}[-1] and 
        ($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME}[-1] and 
        $seq == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}[-1]);


    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}     }, $seq);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME} }, $tcp_ts_val);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME} }, $time + $time_usec / 1000000);
    

    $first_rx_time = $time + $time_usec / 1000000 if($first_rx_time == -1);
    next if($time + $time_usec / 1000000 - $first_rx_time < $discard);

    unless (exists $ip_map{$src}{SHIFT}) {
        $ip_map{$src}{SHIFT} = $time - $ip_map{$src}{SHIFT_TO};
    }

    print FH_OUT join(" ", ($time-$ip_map{$src}{SHIFT}, $time_usec, $ip_map{$src}{TO}, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n";
}
close FH;
close FH_OUT;