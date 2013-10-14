#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/26 @ Narus 
##
## Group packets in flows, and analyze TTL, tput, pkt number, packet length entropy.
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length>
##
## - output
##     ./output/
##     a) file.<id>.total_tput.ts.txt: 
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
##      perl analyze_sprint_text.pl 2013.06.24.AP.pcap.txt
##################################################

use strict;

use MyUtil;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug


#####
## variables
my $output_dir = "./exp2/output";
my $input_dir = "./exp2/text";

my $file_name;
my @tput_ts = ();   ## timeseries of throughput
my @pkt_ts = ();    ## timeseries of number of packet
my $cur_tput = 0;   ## throughput of this second
my $cur_pkt = 0;    ## number of packets of this second
my $cur_time = 0;   ## current second
my $first_time = -1;    ## the start time of the trace
my $last_time;          ## the end time of trace
my %ip_info;        ## to store the information of each IP
                    ## @{ip}{id_ts} - in pkt order, not in second
                    ## @{ip}{ttls}

                    ## @{ip}{ttl_ts}
                    ## @{ip}{tput_ts}
                    ## @{ip}{pkt_ts}
                    ## @{ip}{pkt_size_entropy_ts}

                    ## %{ip}{ttl_cur}: all ttl of this second
                    ## ${ip}{tput_cur}: throughput of this second
                    ## ${ip}{pkt_cur}: number of packet this second
                    ## %{ip}{pkt_size_entropy_cur}: all packet length of this second


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
print "input file = $file_name\n" if($DEBUG1);
my @dir_structure = split(/\//, $file_name);


#####
## main starts here
open FH, "$input_dir/$file_name" or die $!;
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


    ## update time
    $first_time = $time if($first_time < 0);
    $last_time = $time;


    ## update ip info
    if(!(exists $ip_info{$ip_pair}{start_time})) {
        ## the first time this IP pair is obervered
        $ip_info{$ip_pair}{start_time} = $time;

        ## add 0s to the beginning
        foreach ($first_time .. $time - 1) {
            push(@{$ip_info{$ip_pair}{ttl_ts}}, 0);
            push(@{$ip_info{$ip_pair}{tput_ts}}, 0);
            push(@{$ip_info{$ip_pair}{pkt_ts}}, 0);
            push(@{$ip_info{$ip_pair}{pkt_size_entropy_ts}}, 0);
        }
    }
    push(@{$ip_info{$ip_pair}{id_ts}}, $id);
    $ip_info{$ip_pair}{ttls}{$ttl} = 1;
            

    ## time proceed to next second
    if($cur_time != $time) {
        
        ## DEBUG
        print "$time\n" if($DEBUG1);
        if($DEBUG0) {
            if(abs($cur_time - $time) > 1) {
                print STDERR "the time jump more than 1 second...\n";
            }    
        }

        $cur_time = $time;


        ## update timeseries
        push(@tput_ts, $cur_tput);
        push(@pkt_ts, $cur_pkt);


        ## update tput and packet_cnt
        $cur_tput = $len;
        $cur_pkt = 1;


        ## update ip info timeseries
        foreach my $this_ip_pair (keys %ip_info) {
            push(@{$ip_info{$this_ip_pair}{ttl_ts}}, scalar(keys %{$ip_info{$this_ip_pair}{ttl_cur}}));
            push(@{$ip_info{$this_ip_pair}{tput_ts}}, $ip_info{$this_ip_pair}{tput_cur});
            push(@{$ip_info{$this_ip_pair}{pkt_ts}}, $ip_info{$this_ip_pair}{pkt_cur});
            push(@{$ip_info{$this_ip_pair}{pkt_size_entropy_ts}}, MyUtil::cal_entropy(\%{$ip_info{$this_ip_pair}{pkt_size_entropy_cur}}));


            #####
            ## DEBUG
            #####
            if($DEBUG1) {
                if(scalar(keys %{$ip_info{$this_ip_pair}{ttl_cur}}) > 1) {
                    print "all time: ".$this_ip_pair.", ".scalar(keys %{$ip_info{$this_ip_pair}{ttls}}).", ".join(", ", keys %{$ip_info{$this_ip_pair}{ttls}})."\n";
                    print "this sec: ".$this_ip_pair.", ".scalar(keys %{$ip_info{$this_ip_pair}{ttl_cur}}).", ".join(", ", keys %{$ip_info{$this_ip_pair}{ttl_cur}})."\n";    
                }
            }


            ## clean ip info of current second
            %{$ip_info{$this_ip_pair}{ttl_cur}} = ();
            $ip_info{$this_ip_pair}{tput_cur} = 0;
            $ip_info{$this_ip_pair}{pkt_cur} = 0;
            %{$ip_info{$this_ip_pair}{pkt_size_entropy_cur}} = ();
        }
        
        ## update ip info of current second
        $ip_info{$ip_pair}{ttl_cur}{$ttl} = 1;
        $ip_info{$ip_pair}{tput_cur} = $len;
        $ip_info{$ip_pair}{pkt_cur} = 1;
        $ip_info{$ip_pair}{pkt_size_entropy_cur}{$len} = 1;
    }

    ## still in the same second
    else {
        ## update tput and packet_cnt
        $cur_tput += $len;
        $cur_pkt ++;

        ## update ip info of current second
        $ip_info{$ip_pair}{ttl_cur}{$ttl} = 1; ## change this to count might reduce false alarm
        $ip_info{$ip_pair}{tput_cur} += $len;
        $ip_info{$ip_pair}{pkt_cur} ++;
        $ip_info{$ip_pair}{pkt_size_entropy_cur}{$len} ++;
    }
}
close FH;

## XXX: last second info is lost


#####
## output results
print "\n\n output:\n";

#####
## DEBUG
#####
if($DEBUG0) {
    print "Interval: $first_time-$last_time = ".($last_time - $first_time + 1)."\n";
    print "number of elements in timeseries: tput=".@tput_ts.", pkt=".@pkt_ts."\n";
}

## total
my $total_tput = 0;
my $total_pkt = 0;
$total_tput += $_ for @tput_ts;
$total_tput /= ($last_time - $first_time + 1);
$total_pkt += $_ for @pkt_ts;
print "tput=$total_tput, #pkt=$total_pkt\n";
print "number of dst>src pairs = ".scalar(keys(%ip_info))."\n";

open FH, "> $output_dir/$file_name.total_tput.ts.txt" or die $!;
print FH join(", ", @tput_ts);
close FH;

open FH, "> $output_dir/$file_name.pkt.ts.txt" or die $!;
print FH join(", ", @pkt_ts);
close FH;

## individual
open FH_ID, "> $output_dir/$file_name.ids.ts.txt" or die $!;
open FH_TTL, "> $output_dir/$file_name.ttl.txt" or die $!;
open FH_TTL_TS, "> $output_dir/$file_name.ttl.ts.txt" or die $!;
open FH_TPUT, "> $output_dir/$file_name.tput.ts.txt" or die $!;
open FH_PKT, "> $output_dir/$file_name.pkt.ts.txt" or die $!;
open FH_ENT, "> $output_dir/$file_name.len_entropy.ts.txt" or die $!;
foreach my $this_ip_pair (keys %ip_info) {
    
    ## id
    print FH_ID $this_ip_pair.", ".scalar(@{$ip_info{$this_ip_pair}{id_ts}}).", ".join(", ", @{$ip_info{$this_ip_pair}{id_ts}})."\n";

    ## ttl
    print FH_TTL $this_ip_pair.", ".scalar(keys %{$ip_info{$this_ip_pair}{ttls}}).", ".join(", ", keys %{$ip_info{$this_ip_pair}{ttls}})."\n";
    print FH_TTL_TS $this_ip_pair.", ".join(", ", @{$ip_info{$this_ip_pair}{ttl_ts}})."\n";


    ## tput
    print FH_TPUT $this_ip_pair.", ".join(", ", @{$ip_info{$this_ip_pair}{tput_ts}})."\n";

    ## pkt
    print FH_PKT $this_ip_pair.", ".join(", ", @{$ip_info{$this_ip_pair}{pkt_ts}})."\n";

    ## entropy
    print FH_ENT $this_ip_pair.", ".join(", ", @{$ip_info{$this_ip_pair}{pkt_size_entropy_ts}})."\n";    
}
close FH_ID;
close FH_TTL;
close FH_TTL_TS;
close FH_TPUT;
close FH_PKT,;
close FH_ENT;

1;


#####
## functions
