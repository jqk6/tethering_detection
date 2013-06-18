#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/17 @ Narus 
##
## Group packets in flows, and analyze TTL, tput, pkt number, packet length entropy.
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
##
## - output
##     ./output/
##     a) file.<id>.tput.ts.txt: 
##         total throughput timeseries
##     b) file.<id>.pkt.ts.txt
##         total packet number timeseries
##     c) file.<id>.ids.ts.txt
##         IP ID of each packet of each flow
##     d) file.<id>.ttl.txt
##         TTL of each flow
##     e) file.<id>.ttl.ts.txt
##         timeseries of # of unique TTLs of each flow
##     f) file.<id>.tput.ts.txt
##         timeseries of tput of each flow
##     g) file.<id>.pkt.ts.txt
##         timeseries of # of packets of each flow
##     i) file.$file_id.len_entropy.ts.txt
##         timeseries of packet len entropy of each flow
##
##  e.g.
##      perl analyze_sprint_tcp_seq.pl /data/ychen/sprint/text2/omni.out.49.eth.pcap.txt
##################################################

use strict;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug


#####
## variables
my $output_dir = "./output_tcp";

my $file_name;
my $file_id;

my %ip_info;        ## ip pair seq and ack info
                    ## {src ip}{src port}{dst ip}{dst port}{time}{seq}
                    ## {src ip}{src port}{dst ip}{dst port}{time}{ack}
                    ## {src ip}{src port}{dst ip}{dst port}{time}{payload_len}


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
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len))."\n" if($DEBUG1);


    $ip_info{$src}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{seq} = $seq;
    $ip_info{$src}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{ack} = $ack;
    $ip_info{$src}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{is_ack} = $is_ack;
    $ip_info{$src}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{payload_len} = $payload_len;

}
close FH;


#####
## Output
print STDERR "start to print result..\n" if($DEBUG2);
my %checked_ips;        ## stored ips which are already checked, so we don't need to check them again
foreach my $this_src_ip (keys %ip_info) {
    foreach my $this_src_port (keys %{ $ip_info{$this_src_ip} }) {
        foreach my $this_dst_ip (keys %{ $ip_info{$this_src_ip}{$this_src_port} }) {
            foreach my $this_dst_port (keys %{ $ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip} }) {

                ## check if this IP pair is already checked
                if(exists($checked_ips{"$this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port"}) or
                   exists($checked_ips{"$this_dst_ip:$this_dst_port>$this_src_ip:$this_src_port"})
                ) {
                    print "$this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port is already ehcecked\n" if($DEBUG1);
                    next;
                }
                else {
                    $checked_ips{"$this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port"} = 1;
                }


                ## if not checked
                print "- $this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port\n";

                my @src_times = sort {$a <=> $b} (keys %{ $ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port} });
                my @dst_times = sort {$a <=> $b} (keys %{ $ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port} });

                my $src_ind = 0;
                my $dst_ind = 0;
                while($src_ind < scalar(@src_times) and $dst_ind < scalar(@dst_times) ) {
                    my $this_src_time = $src_times[$src_ind];
                    my $this_dst_time = $dst_times[$dst_ind];

                    if($this_src_time < $this_dst_time) {
                        ## print src info
                        print "$this_src_time s>d: seq=".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{seq}."(".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{payload_len}.")".($ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{seq}+$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{payload_len}).", ack=".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{ack}."(".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{is_ack}.")\n";
                        $src_ind ++;
                    }
                    elsif($this_src_time > $this_dst_time) {
                        ## print src info
                        print "$this_dst_time d>s: seq=".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{seq}."(".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{payload_len}.")".($ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{seq}+$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{payload_len}).", ack=".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{ack}."(".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{is_ack}.")\n";
                        $dst_ind ++;
                    }
                    else {
                        ## send and ack at the same time??
                        ## print both ...
                        print "$this_src_time s>d: seq=".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{seq}."(".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{payload_len}.")".($ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{seq}+$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{payload_len}).", ack=".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{ack}."(".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{is_ack}.")\n";
                        print "$this_dst_time d>s: seq=".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{seq}."(".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{payload_len}.")".($ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{seq}+$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{payload_len}).", ack=".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{ack}."(".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{is_ack}.")\n";

                        $src_ind ++;
                        $dst_ind ++;
                    }
                }
                ## src or dst may not finish yet
                while($src_ind < scalar(@src_times)) {
                    print "src hasn't finished:\n" if($DEBUG1);

                    my $this_src_time = $src_times[$src_ind];
                    print "$this_src_time s>d: seq=".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{seq}."(".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{payload_len}.")".($ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{seq}+$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{payload_len}).", ack=".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{ack}."(".$ip_info{$this_src_ip}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{is_ack}.")\n";

                    $src_ind ++;
                }
                while($dst_ind < scalar(@dst_times) ) {
                    print "dst hasn't finished:\n" if($DEBUG1);

                    my $this_dst_time = $dst_times[$dst_ind];
                    print "$this_dst_time d>s: seq=".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{seq}."(".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{payload_len}.")".($ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{seq}+$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{payload_len}).", ack=".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{ack}."(".$ip_info{$this_dst_ip}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{is_ack}.")\n";

                    $dst_ind ++;
                }
            }
        }
    }
}


