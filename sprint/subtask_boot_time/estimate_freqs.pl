#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/18 @ Narus
##
## Calculate frequency of machines using TCP Timestamp
##
## - input: 
##     a) parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##     b) threshold
##
## - output
##
## - internal variables
##     e) FIX_DEST  : only target the pkts to some destination node
##     f) THRESHOLD : only IP with # of pkts > THRESHOLD will be analyzed
##
##  e.g.
##      perl estimate_freqs.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt
##################################################


use strict;
use MyBootTime;



#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $FIX_DEST      = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DEST_ADDR = "192.168.5.67";
my $THRESHOLD     = 200;

#####
## variables

my $file_name;
my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}


#####
## check input
if(@ARGV < 1) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
my @tmp = split(/\//, $file_name);
my $pure_name = pop(@tmp);
print "input file = $file_name\n" if($DEBUG1);
print "input file name = $pure_name\n" if($DEBUG2);

if(@ARGV == 2) {
    $THRESHOLD = $ARGV[1] + 0;
}


#####
## main starts here
print STDERR "start to read data..\n" if($DEBUG1);
open FH, "$file_name" or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);

    ## convert string to numbers
    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;


    next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME}{$time + $time_usec / 1000000} = 1;
}
close FH;



#####
## estimate the frequency
print STDERR "start to estimate frequency..\n" if($DEBUG1);

foreach my $this_ip (keys %{ $ip_info{IP} }) {

    if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD) {
        delete $ip_info{IP}{$this_ip};
        next;
    }

    my ($freq, $likelihood) = MyBootTime::estimate_frequency(\%{ $ip_info{IP}{$this_ip} });
    print "  $this_ip(".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} })."): frequency = $freq, likelihood = $likelihood\n";
}


