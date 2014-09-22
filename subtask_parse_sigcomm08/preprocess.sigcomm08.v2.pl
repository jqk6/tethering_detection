#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2014.04.14 @ UT Austin
##
## filter out:
## - pkts: reordering of Timestamp
## - pkts: UDP
## - flow w/o enough packets
## - flow too short
## - flow w/ multiple TTLs
## - flow w/o monotonic TS
## - IP w/o enough packets
## - IP w/o UA
## - IP w/o same freq
## - IP w/o same boot time
##
## filter out packets which is:
##
## - input:
##
## - output:
##
## - e.g.
##    perl preprocess.sigcomm08.v2.pl 4
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use lib "../utils";

use Tethering;
use TetheringFeatures;


#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print output

my $NUM_PKT_PER_FLOW = 50;
my $FLOW_LEN = 20; ## in seconds
my $NUM_FLOW_PER_IP = 2;

my $DO_PKT_REORDERING = 1;
my $DO_PKT_UDP        = 1;
my $DO_FLOW_PKT_NUM   = 1;
my $DO_FLOW_LEN       = 1;
my $DO_FLOW_TTL_NUM   = 0;
my $DO_FLOW_TS_MONO   = 0;
my $DO_IP_FLOW_NUM    = 1;
my $DO_IP_USER_AGENT  = 0;
my $DO_IP_FREQ        = 1;
my $DO_IP_BOOT_TIME   = 0;

#############
# Constants
#############


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_parse_sigcomm08/tshark";
my $output_dir = "../processed_data/subtask_parse_sigcomm08/tshark";

my $monitor;
# my %filenames = ();
my $filename = "sigcomm08";
my $output_filename = "sigcomm08";
my %ip_info = ();


#############
# check input
#############
if(@ARGV != 1) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$monitor = $ARGV[0];
$filename .= ".$monitor";
$output_filename .= ".$monitor";


#############
# Main starts
#############

## read the filename
my $prev_rcv_time = 0;
open FH, "bzcat $input_dir/$filename.txt.bz2 | " or die $!;
while(<FH>) {
    chomp;
    print $_."\n" if($DEBUG0);

    my ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $_);
    next if($src =~ /,/);

    $cnt += 0; $rcv_time += 0; $id = hex($id); $ttl += 0; $tsval += 0; $tsecr += 0; $wsscale += 0; $inflight += 0;
    print "  src=$src, dst=$dst, id=$id, ttl=$ttl, ts=$tsval, win scale=$wsscale, opt=$opt_kind, UA=$ua, flight bytes=$inflight\n" if($DEBUG0);

    my $new_line = join("|", ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));


    ## filter out packets
    if($rcv_time < $prev_rcv_time) {
        print "  rcv time < prev rcv time\n";
        next;
    }
    $prev_rcv_time = $rcv_time;

    #############
    ## - pkt w/ reordering of Timestamp
    #############
    if($DO_PKT_REORDERING) {
        if($tsval > 0) {
            if($ip_info{SRC}{$src}{PREV_TS}{TIME} > 0 and $tsval == $ip_info{SRC}{$src}{PREV_TS}{TIME}) {
                next;
            }
            elsif($ip_info{SRC}{$src}{PREV_TS}{TIME} > 0 and $tsval <= $ip_info{SRC}{$src}{PREV_TS}{TIME}) {
                # print "prev: ".$ip_info{SRC}{$src}{PREV_TS}{TIME}."\n"; 
                # print "curr: $tsval\n";
                # print ".";
                next;
            }
            $ip_info{SRC}{$src}{PREV_TS}{TIME} = $tsval;
            # $ip_info{SRC}{$src}{PREV_TS}{LINE} = $new_line;
        }
    }

    #############
    ## - pkt: UDP
    #############
    if($DO_PKT_UDP) {
        # print "o";
        next if($dport == 0);
    }


    ## packets we want
    $ip_info{SRC}{$src}{RCV_TIME}{$rcv_time}{LINE}{$new_line} = 0;
    $ip_info{SRC}{$src}{CONN}{"$dst,$sport,$dport"}{RCV_TIME}{$rcv_time}{LINE} = $new_line;
    $ip_info{SRC}{$src}{CONN}{"$dst,$sport,$dport"}{TTL}{$ttl} = 1;
    
    if($tsval != 0) {
        # $ip_info{SRC}{$src}{CONN}{"$dst,$sport,$dport"}{RX_TIME}{$rcv_time}{TX_TIME} = $tsval if($tsval > 0);
        push( @{ $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{TX_TIME} }, $tsval);
        push( @{ $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{RX_TIME} }, $rcv_time);
    
        $ip_info{SRC}{$src}{ALL_FLOW}{RX_TIME}{$rcv_time}{TX_TIME} = $tsval;
        # push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{TX_TIME} }, $tsval);
        # push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{RX_TIME} }, $rcv_time);
    }
    $ip_info{SRC}{$src}{UA}{$ua} = 0;
}
close FH;

##########################################################

my %ok_ip_info = ();
foreach my $this_ip (sort (keys %{ $ip_info{SRC} })) {
    print "$this_ip\n" if($DEBUG2);

    # my %ok_flow_info = ();
    foreach my $this_flow (keys %{ $ip_info{SRC}{$this_ip}{CONN} }) {
        #############
        ## number of pkts per flow
        #############
        if($DO_FLOW_PKT_NUM) {
            # print "- flow: number of pkts per flow\n" if($DEBUG2);

            my $num_pkts = scalar(keys %{ $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RCV_TIME} });
            # print "  flow: #pkt=$num_pkts\n";
            if($num_pkts > $NUM_PKT_PER_FLOW) {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 0;
                next;
            }
        }

        #############
        ## length of flow
        #############
        if($DO_FLOW_LEN) {
            # print "- flow: length of flow\n" if($DEBUG2);

            my @rx_times = (sort {$a <=> $b} (keys %{ $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RCV_TIME} }));
            my $flow_len = $rx_times[-1] - $rx_times[0];
            print "  flow: len=$flow_len\n";
            if($flow_len > $FLOW_LEN) {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 0;
                next;
            }
        }

        #############
        ## flow w/ multiple TTLs
        #############
        if($DO_FLOW_TTL_NUM) {
            # print "- flow: w/ multiple TTLs\n" if($DEBUG2);

            my $num_ttls = scalar(keys $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{TTL});
            if($num_ttls == 1) {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 0;
                next;
            }
        }

        #############
        ## flow w/o monotonic TS
        #############
        if($DO_FLOW_TS_MONO) {
            # print "- flow: w/o monotonic TS\n" if($DEBUG2);

            my $is_mono = 1;
            my $prev_tx_time = -1;
            # foreach my $rx_time (keys %{ $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RX_TIME} }) {
            foreach my $ti (0 .. @{ $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RX_TIME} }-1) {
                my $rx_time = $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RX_TIME}[$ti];
                my $tx_time = $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{TX_TIME}[$ti];
                if($tx_time < $prev_tx_time) {
                    ## disorder
                    $is_mono = 0;
                    last;
                }
                $prev_tx_time = $tx_time;
            }

            if($is_mono == 1) {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} = 0;
                next;
            }
        }


        #############
        ## Final step for this flow:
        ##   this flow is OK
        #############
        if($ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} == 1) {
            $ok_ip_info{SRC}{$this_ip}{OK_FLOWS}{$this_flow} = 1;
        }
        else {
            die "should not be here \n";
        }
    } ## end of flows


    #############
    ## - IPs: at least a flow has enough packet
    #############
    if($DO_IP_FLOW_NUM) {
        print "- IP: has enough flows\n" if($DEBUG2);
        
        my $num_flows = scalar(keys %{ $ok_ip_info{SRC}{$this_ip}{OK_FLOWS} });
        print "  # flows=$num_flows\n" if($DEBUG2);
        if($num_flows >= $NUM_FLOW_PER_IP) {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 1;
        }
        else {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 0;
            next;
        }
    }


    #############
    ## - IPs: has UA
    #############
    if($DO_IP_USER_AGENT) {
        print "- IP: has UA\n" if($DEBUG2);
        
        my @this_ua = keys %{ $ip_info{SRC}{$this_ip}{UA} };
        my @oss = Tethering::identify_os(\@this_ua);
        if(scalar(@oss) > 0) {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 1;
            print "  ".join(",". @oss)."\n";
        }
        else {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 0;
            print "  no\n";
            next;
        }
    }

    #############
    ## - IPs: freq is stable
    #############
    if($DO_IP_FREQ) {
        print "- IP: freq is stable\n" if($DEBUG2);

        my %tmp_flow_info;
        foreach my $this_flow (keys %{ $ip_info{SRC}{$this_ip}{CONN} }) { 
            next if($ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} != 1);
            
            if(exists $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RX_TIME}) {
                push(@{ $tmp_flow_info{CONN}{$this_flow}{RX_TIME} }, @{ $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RX_TIME} });
                push(@{ $tmp_flow_info{CONN}{$this_flow}{TX_TIME} }, @{ $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{TX_TIME} });
            }
        }

        my ($this_freq, $freq_stdev) = TetheringFeatures::flow_frequency_stable_stdev(\%tmp_flow_info, 1000);
        
        if($freq_stdev < 10) {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 1;
            print "  stdev=$freq_stdev\n";
        }
        else {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 0;
            print "  no: stdev=$freq_stdev\n";
            next;
        }
    }


    #############
    ## Final step for this IP:
    ##   this IP is OK
    #############
    if($ok_ip_info{SRC}{$this_ip}{STATE} == 1) {
        $ok_ip_info{OK_SRC}{$this_ip} = 1;
    }
    else {
        die "should not be here (IP) \n";
    }
}

print "> # IPs: ".scalar(keys %{ $ok_ip_info{OK_SRC} })."\n";
print "    ".join("\n    ", (sort keys %{ $ok_ip_info{OK_SRC} }))."\n";


#############
## output the new file
#############
print "output the new file\n" if($DEBUG2);

if(-e "$output_dir/$output_filename.filter.txt.bz2") {
    my $cmd = "rm \"$output_dir/$output_filename.filter.txt.bz2\"";
    `$cmd`;
}

my %tmp = ();
foreach my $this_ip (sort (keys %{ $ip_info{SRC} })) {
    next if($ok_ip_info{SRC}{$this_ip}{STATE} != 1);

    foreach my $this_flow (keys %{ $ip_info{SRC}{$this_ip}{CONN} }) { 
        next if($ok_ip_info{SRC}{$this_ip}{CONN}{$this_flow}{STATE} != 1);

        foreach my $rx_time (keys %{ $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RCV_TIME} }) { 
            my $line = $ip_info{SRC}{$this_ip}{CONN}{$this_flow}{RCV_TIME}{$rx_time}{LINE};

            $tmp{RCV_TIME}{$rx_time}{LINE}{$line} = 1;
        }
    }
}

open FH_OUT, "> $output_dir/$output_filename.filter.txt" or die $!;
foreach my $rx_time (sort {$a <=> $b} (keys %{ $tmp{RCV_TIME} })) {
    foreach my $this_line (keys %{ $tmp{RCV_TIME}{$rx_time}{LINE} }) {
        print FH_OUT "$this_line\n";
    }
}
close FH_OUT;


#############
## compress the new output file
#############
print "compress the new output file\n" if($DEBUG2);

my $cmd = "bzip2 \"$output_dir/$output_filename.filter.txt\"";
`$cmd`;


