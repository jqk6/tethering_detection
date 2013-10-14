#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - replace_ip.pl <text dir> <exp index> <replace ratio>
##      e.g.
##      perl replace_ip.pl text5 0 0.01
##
##########################################

use strict;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1;


#############
# Constants
#############
my $FIX_DST      = 0; ## 1 to fix the TCP destination
my $FIX_DST_ADDR = "192.168.5.67";
my $FIX_SRC      = 0; ## 1 to fix the TCP src
my $FIX_SRC_ADDR = "^28\.";

my $MIN_NUM_PKTS = 100;


#############
# Variables
#############
my $input_dir = "../../processed_data/mawi";
my $text_dir = "test5";
my $exp = 0;
my $replaced_ratio = 0.02;

my %ip_info = ();
my %src_ips = ();
my %dst_ips = ();
my %ip_mapping = ();



#############
# check input
#############
if(@ARGV != 3) {
    print "wrong number of input\n";
    exit;
}
$text_dir = $ARGV[0];
$exp = $ARGV[1] + 0;
$replaced_ratio = $ARGV[2] + 0;
print "Exp $exp\n" if($DEBUG2);
print "  dir: $input_dir/$text_dir\n" if($DEBUG2);
print "  replaced ratio: $replaced_ratio\n" if($DEBUG2);


#############
# Main starts
#############

#############
## Open the dir and files to get all IPs
#############
print "Open the dir and files to get all IPs\n" if($DEBUG2);
opendir(DIR, "$input_dir/$text_dir") or die $!;
while (my $file = readdir(DIR)) {
    next if($file =~ /^\.+$/);
    next if($file =~ /exp\d+.txt$/);


    #############
    ## Read the file
    #############
    ## TCP Timestamp
    print "  start to read TCP Timestamp data: $file\n" if($DEBUG2);
    open FH, "$input_dir/$text_dir/$file" or die $!."\n$input_dir/$text_dir/$file\n";
    while(<FH>) {
        next if($_ =~ /Processed/); ## used to ignore the last line in the input file

        ## format
        ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
        my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);

        ## convert string to numbers
        $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;


        next if($FIX_SRC and (!($src =~ /$FIX_SRC_ADDR/ )));
        next if($FIX_DST and (!($dst =~ /$FIX_DST_ADDR/)));
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

        
        $src_ips{$src} ++;
        $dst_ips{$dst} ++;
    }

}
closedir(DIR);
# exit;

#############
## Filter ips by number of packets first
#############
print "Filter ips by number of packets first\n" if($DEBUG2);
my %filtered_src_ips = ();
my %filtered_dst_ips = ();
foreach my $this_ip (keys %src_ips) {
    $filtered_src_ips{$this_ip} = $src_ips{$this_ip} if($src_ips{$this_ip} > $MIN_NUM_PKTS);
}
foreach my $this_ip (keys %dst_ips) {
    $filtered_dst_ips{$this_ip} = $dst_ips{$this_ip} if($dst_ips{$this_ip} > $MIN_NUM_PKTS);
}


#############
## Decide which IPs are replaced
#############
print "\nDecide which IPs are replaced\n" if($DEBUG2);

my @src_ips = keys %filtered_src_ips;
my $num_src_ips = scalar(@src_ips);
my $replaced_num = $num_src_ips * $replaced_ratio;
my $replaced_cnt = 0;
my %selected_ip_ind = ();
my $sed_cmd = "sed '";

print "  num src IPs: $num_src_ips\n" if($DEBUG2);
print "  num IPs to be replaced: $replaced_num\n" if($DEBUG2);

while($replaced_cnt < $replaced_num) {
    my $from_ip_ind = int(rand($num_src_ips));
    my $to_ip_ind   = int(rand($num_src_ips));
    
    ## src == dst
    next if($from_ip_ind == $to_ip_ind);
    ## src has been selected
    next if($selected_ip_ind{$from_ip_ind} == 1);
    ## dst has been selected
    next if($selected_ip_ind{$to_ip_ind}   == 1);
    

    my $from_ip = $src_ips[$from_ip_ind];
    my $to_ip   = $src_ips[$to_ip_ind];
    $ip_mapping{$from_ip} = $to_ip;
    

    #####
    ## generate sed command
    #####
    print "  $replaced_cnt: $from_ip -> $to_ip\n";
    $sed_cmd .= "s/".join("\\.", split(/\./, $from_ip))."/".join("\\.", split(/\./, $to_ip))."/;";


    $replaced_cnt ++;
}
$sed_cmd .= "'";


#############
## Start to replace IPs in the file
#############
print "\nStart to replace IPs in the file\n" if($DEBUG2);

opendir(DIR, "$input_dir/$text_dir") or die $!;
while (my $file = readdir(DIR)) {
    next if($file =~ /^\.+$/);
    next if($file =~ /exp\d+.txt$/);

    my $cmd = $sed_cmd." $input_dir/$text_dir/$file > $input_dir/$text_dir/$file.exp$exp.txt";
    print "  - $cmd\n" if($DEBUG2);
    `$cmd`;    
}
closedir(DIR);


#############
## Output the IP mapping
#############
print "\nOutput the IP mapping\n" if($DEBUG2);

open FH, "> $input_dir/ip_mapping/exp$exp.txt" or die $!;
foreach my $from_ip (keys %ip_mapping) {
    my $to_ip = $ip_mapping{$from_ip};

    print FH "$from_ip, $to_ip\n";
}
close FH;

