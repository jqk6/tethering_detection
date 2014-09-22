#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## - input:
##
## - output:
##
## - e.g.
##   perl gen_tshark.pl 1 1 1 1
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use lib "/u/yichao/utils/perl";
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
my @IPHONE_TTL = (63,64,65);
my @WINDOWS_TTL = (127,128,129);
my @ANDROID_TTL = (63,64,65);
my $WINDOWS_MULTI_TTL_P = 0.3;
my $IPHONE_MULTI_TTL_P = 0;
my $ANDROID_MULTI_TTL_P = 0;

my $IPHONE_WSSCALE = 16;
my $IPHONE_WSSCALE_P = 0.3;
my $WINDOWS_WSSCALE = 256;
my $WINDOWS_WSSCALE_P = 0.3;
my $ANDROID_WSSCALE = 64;
my $ANDROID_WSSCALE_P = 0.3;

my $IPHONE_OPT_P = 0.9;
my $WINDOWS_OPT_P = 0; #0.1;
my $ANDROID_OPT_P = 0.9;

my $IPHONE_LARGE_ITVL_P = 0.2;
my $IPHONE_LARGE_ITVL = 10;
my $IPHONE_SMALL_ITVL = 2;
my $WINDOWS_LARGE_ITVL_P = 0.3;
my $WINDOWS_LARGE_ITVL = 15;
my $WINDOWS_SMALL_ITVL = 2;
my $ANDROID_LARGE_ITVL_P = 0.2;
my $ANDROID_LARGE_ITVL = 10;
my $ANDROID_SMALL_ITVL = 2;

my $NUM_PKTS = 1000;
my $INIT_TIME = 60;
my $NUM_FLOWs = 2;

my @IPHONE_TICK = (800 .. 1000);
my @WINDOWS_TICK = (200, 250);
my @ANDROID_TICK = (1000);


#############
# Variables
#############
my $input_dir  = "";
my $output_dir = "../processed_data/subtask_sim_trace/tshark";
my $output_filename;

my $num_iphone;
my $num_android;
my $num_windows;

my $seed;

my %ip_info = ();

#############
# check input
#############
if(@ARGV != 4) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$num_iphone  = $ARGV[0]+0;
$num_android = $ARGV[1]+0;
$num_windows = $ARGV[2]+0;
$seed        = $ARGV[3]+0;

$output_filename = "sim.i$num_iphone.a$num_android.w$num_windows.s$seed";


#############
## Main starts
#############

my $dev_id = 0;
my $cnt = 0;
my %tmp_info = ();

## iPhone
foreach my $ii (0 .. $num_iphone-1) {
    my ($rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight);
    my %tmp_info2;
    
    $src = "1.1.1.$dev_id";
    $dev_id ++;
    $ua = "iphone $ii";
    $inflight = 0;
    my $bt_tick = int(rand(86400*5*100));
    my $multi_ttl = 0;
    if(rand() < $IPHONE_MULTI_TTL_P) {
        $multi_ttl = 50; 
    }

    my $flow_ind = 0;
    foreach my $fi (0 .. $NUM_FLOWs-1) {
        $dst = "4.4.4.$flow_ind";
        $flow_ind ++;
        $sport = int(rand(6535))+1;
        $dport = int(rand(6535))+1;
        $ttl = $IPHONE_TTL[int(rand(scalar(@IPHONE_TTL)))] + $multi_ttl;


        my $prev_time = -1;
        my $prev_ts = -1;
        my $prev_id = int(rand(65535));
        foreach my $pi (0 .. $NUM_PKTS-1) {
            $tsecr = 0;
            
            ## tick per second used
            my $tick = $IPHONE_TICK[int(rand(scalar(@IPHONE_TICK)))];

            ## rcv_time and ts
            if($prev_time < 0) {
                ## first packet
                my $itvl = rand($INIT_TIME);
                my $itvl_tick = floor($itvl * $tick);
                $rcv_time = $itvl;
                $tsval = $bt_tick + $itvl_tick;
            }
            else {
                ## interval from previous packet
                my $itvl = rand($IPHONE_SMALL_ITVL);
                if(rand() < $IPHONE_LARGE_ITVL_P) {
                    $itvl = rand($IPHONE_LARGE_ITVL); 
                }
                my $itvl_tick = floor($itvl * $tick);
                
                $rcv_time = $prev_time + $itvl;
                $tsval = $prev_ts + $itvl_tick;
            }
            $prev_time = $rcv_time;
            $prev_ts = $tsval;
            
            ## id
            $id = int(rand(65535));
            $prev_id = $id;
            
            ## wsscale
            $wsscale = "";
            if(rand() < $IPHONE_WSSCALE_P) {
                $wsscale = $IPHONE_WSSCALE;
            }
            
            ## opt kind
            $opt_kind = "";
            if(rand() < $IPHONE_OPT_P) {
                $opt_kind = "8";
            }
            else {
                $tsval = "";
                $tsecr = "";
            }

            ## finish this packt
            my $line = join("|", ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
            $tmp_info2{RX_TIME}{$rcv_time}{LINE}{$line} = 1;
            # print "$line\n";
            $cnt ++;
        }
    }

    ## update tsval
    my $prev_rcv_time = -1;
    my $prev_ts;
    foreach my $this_rt (sort {$a <=> $b} (keys %{ $tmp_info2{RX_TIME} })) {
        foreach my $this_line (keys %{ $tmp_info2{RX_TIME}{$this_rt}{LINE} }) {
            my ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $this_line);

            ## no tcp timestamp
            if($opt_kind ne "8") {
                $tmp_info{RX_TIME}{$rcv_time}{LINE}{$this_line} = 1;
                # print "$this_line\n";
                next;
            }

            my $new_ts;
            if($prev_rcv_time < 0) {
                ## first packet
                $new_ts = $tsval;
            }
            else {
                ## tick per second used
                my $tick = $IPHONE_TICK[int(rand(scalar(@IPHONE_TICK)))];
                my $itvl_tick = floor( ($rcv_time-$prev_rcv_time) * $tick);
                $new_ts = $prev_ts + $itvl_tick;
            }
            my $new_line = join("|", ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $new_ts, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
            $tmp_info{RX_TIME}{$rcv_time}{LINE}{$new_line} = 1;
            # print "$new_line\n";
            
            $prev_rcv_time = $rcv_time;
            $prev_ts = $new_ts;
        }
    }
}


## Android
foreach my $ii (0 .. $num_android-1) {
    my ($rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight);
    my %tmp_info2;
    
    $src = "1.1.1.$dev_id";
    $dev_id ++;
    $ua = "android $ii";
    $inflight = 0;
    my $tick = $ANDROID_TICK[int(rand(scalar(@ANDROID_TICK)))];   ## tick per second used
    my $bt_tick = int(rand(86400*5*100));
    my $multi_ttl = 0;
    if(rand() < $ANDROID_MULTI_TTL_P) {
        $multi_ttl = 50; 
    }

    my $flow_ind = 0;
    foreach my $fi (0 .. $NUM_FLOWs-1) {
        $dst = "4.4.4.$flow_ind";
        $flow_ind ++;
        $sport = int(rand(6535))+1;
        $dport = int(rand(6535))+1;
        $ttl = $ANDROID_TTL[int(rand(scalar(@ANDROID_TTL)))] + $multi_ttl;


        my $prev_time = -1;
        my $prev_ts;
        my $prev_id;
        foreach my $pi (0 .. $NUM_PKTS-1) {
            $tsecr = 0;
    
            ## rcv_time, ts, and id
            if($prev_time < 0) {
                ## first packet
                my $itvl = rand($INIT_TIME);
                my $itvl_tick = floor($itvl * $tick);
                $rcv_time = $itvl;
                $tsval = $bt_tick + $itvl_tick;
                
                $id = int(rand(65535));
            }
            else {
                ## interval from previous packet
                my $itvl = rand($ANDROID_SMALL_ITVL);
                if(rand() < $ANDROID_LARGE_ITVL_P) {
                    $itvl = rand($ANDROID_LARGE_ITVL); 
                }
                my $itvl_tick = floor($itvl * $tick);
                
                $rcv_time = $prev_time + $itvl;
                $tsval = $prev_ts + $itvl_tick;

                $id = $prev_id + int(rand(10)) + 1;
            }            
            $prev_time = $rcv_time;
            $prev_ts = $tsval;
            $prev_id = $id;
            

            ## wsscale
            $wsscale = "";
            if(rand() < $ANDROID_WSSCALE_P) {
                $wsscale = $ANDROID_WSSCALE;
            }
            
            ## opt kind
            $opt_kind = "";
            if(rand() < $ANDROID_OPT_P) {
                $opt_kind = "8";
            }
            else {
                $tsval = "";
                $tsecr = "";
            }

            ## finish this packt
            my $line = join("|", ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
            $tmp_info2{RX_TIME}{$rcv_time}{LINE}{$line} = 1;
            # print "$line\n";
            $cnt ++;
        }
    }

    foreach my $this_rt (sort {$a <=> $b} (keys %{ $tmp_info2{RX_TIME} })) {
        foreach my $this_line (keys %{ $tmp_info2{RX_TIME}{$this_rt}{LINE} }) {
            # print "$this_line\n";
            $tmp_info{RX_TIME}{$this_rt}{LINE}{$this_line} = 1;
        }
    }
}



## Windows
foreach my $ii (0 .. $num_windows-1) {
    my ($rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight);
    my %tmp_info2;
    
    $src = "1.1.1.$dev_id";
    $dev_id ++;
    $ua = "windows $ii";
    $inflight = 0;
    my $tick = $WINDOWS_TICK[int(rand(scalar(@WINDOWS_TICK)))];   ## tick per second used
    my $bt_tick = int(rand(86400*5*100));
    my $multi_ttl = 0;
    if(rand() < $WINDOWS_MULTI_TTL_P) {
        $multi_ttl = 50; 
    }

    my $flow_ind = 0;
    foreach my $fi (0 .. $NUM_FLOWs-1) {
        $dst = "4.4.4.$flow_ind";
        $flow_ind ++;
        $sport = int(rand(6535))+1;
        $dport = int(rand(6535))+1;
        $ttl = $WINDOWS_TTL[int(rand(scalar(@WINDOWS_TTL)))] + $multi_ttl;


        my $prev_time = -1;
        my $prev_ts;
        my $prev_id;
        foreach my $pi (0 .. $NUM_PKTS-1) {
            $tsecr = 0;
    
            ## rcv_time, ts, and id
            if($prev_time < 0) {
                ## first packet
                my $itvl = rand($INIT_TIME);
                my $itvl_tick = floor($itvl * $tick);
                $rcv_time = $itvl;
                $tsval = $bt_tick + $itvl_tick;
                
                $id = int(rand(65535));
            }
            else {
                ## interval from previous packet
                my $itvl = rand($WINDOWS_SMALL_ITVL);
                if(rand() < $WINDOWS_LARGE_ITVL_P) {
                    $itvl = rand($WINDOWS_LARGE_ITVL); 
                }
                my $itvl_tick = floor($itvl * $tick);
                
                $rcv_time = $prev_time + $itvl;
                $tsval = $prev_ts + $itvl_tick;

                $id = $prev_id + int(rand(10)) + 1;
            }
            $prev_time = $rcv_time;
            $prev_ts = $tsval;
            $prev_id = $id;
            

            ## wsscale
            $wsscale = "";
            if(rand() < $WINDOWS_WSSCALE_P) {
                $wsscale = $WINDOWS_WSSCALE;
            }
            
            ## opt kind
            $opt_kind = "";
            if(rand() < $WINDOWS_OPT_P) {
                $opt_kind = "8";
            }
            else {
                $tsval = "";
                $tsecr = "";
            }

            ## finish this packt
            my $line = join("|", ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
            $tmp_info2{RX_TIME}{$rcv_time}{LINE}{$line} = 1;
            # print "$line\n";
            $cnt ++;
        }
    }

    ## update IP ID
    my $prev_id = -1;
    foreach my $this_rt (sort {$a <=> $b} (keys %{ $tmp_info2{RX_TIME} })) {
        foreach my $this_line (keys %{ $tmp_info2{RX_TIME}{$this_rt}{LINE} }) {
            my ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $this_line);

            my $new_id;
            if($prev_id < 0) {
                ## first packet
                $new_id = $id;
            }
            else {
                $new_id = $prev_id + 1;
            }
            my $new_line = join("|", ($cnt, $rcv_time, $src, $dst, $sport, $dport, $new_id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
            $tmp_info{RX_TIME}{$rcv_time}{LINE}{$new_line} = 1;
            # print "$new_line\n";
            
            $prev_id = $new_id;
        }
    }
}



## update cnt
my $new_cnt = 0;
foreach my $this_rt (sort {$a <=> $b} (keys %{ $tmp_info{RX_TIME} })) {
    foreach my $this_line (keys %{ $tmp_info{RX_TIME}{$this_rt}{LINE} }) {
        my ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $this_line);

        my $new_line = join("|", ($new_cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
        $ip_info{RX_TIME}{$rcv_time}{LINE}{$new_line} = 1;
        # print "$new_line\n";
        
        $new_cnt ++;
    }
}


# exit;

#############
## output file
#############
print "output file\n";

if(-e "$output_dir/$output_filename.txt.bz2") {
    my $cmd = "rm \"$output_dir/$output_filename.txt.bz2\"";
    `$cmd`;
}

open FH_OUT, "> $output_dir/$output_filename.txt" or die $!;
foreach my $this_rt (sort {$a <=> $b} (keys %{ $ip_info{RX_TIME} })) {
    foreach my $this_line (keys %{ $ip_info{RX_TIME}{$this_rt}{LINE} }) {
        print FH_OUT "$this_line\n";
    }
}
close FH_OUT;



#############
## compress output file
#############
print "compress output file\n";
my $cmd = "bzip2 \"$output_dir/$output_filename.txt\"";
`$cmd`;
