#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## - input: 
##   1. file_name
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##    
##
## - detect_tethering.pl file_name
##      e.g.
##      perl detect_tethering.pl 201101091400.dump.txt.exp0.txt
##
##########################################

use lib "/export/home/ychen/utils";

use strict;
use Tethering;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1;     ## program flow
my $DEBUG3 = 1;     ## results


#############
# Constants
#############
my $FIX_DST      = 0; ## 1 to fix the TCP destination
my $FIX_DST_ADDR = "192.168.5.67";
my $FIX_SRC      = 0; ## 1 to fix the TCP src
my $FIX_SRC_ADDR = "^28\.";

my $MIN_NUM_PKTS = 0;


#############
# Variables
#############
my $input_dir = "/data/ychen/mawi/text5";
my $output_dir = "/data/ychen/output/mawi/tether_ips";

my $file_name;
my %ip_info = ();
my %tethered_ips = ();
my %non_tethered_ips = ();
my $heuristic;


#############
# check input
#############
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
print "file: $input_dir/$file_name\n" if($DEBUG2);


#############
# Main starts
#############
#############
## Read the file
#############
## TCP Timestamp
print "Start to read TCP Timestamp data\n" if($DEBUG2);
open FH, "$input_dir/$file_name" or die $!."\n$input_dir/$file_name\n";
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
    $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;

    $ip_info{IP}{$src}{ALL_FLOW}{RX_TIME}{$time + $time_usec / 1000000}{TX_TIME} = $tcp_ts_val;
    $ip_info{IP}{$src}{ALL_FLOW}{TTL}{$ttl} = 1;
}


#############
## Check Heuristics
#############
print "Check Heuristics\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    #############
    ## Check TTL Heuristic
    #############
    my @ttls = (keys %{ $ip_info{IP}{$this_ip}{ALL_FLOW}{TTL} });
    
    $heuristic = "ttl_num";
    print "  $heuristic\n" if($DEBUG0);
    my $if_tether = Tethering::check_ttl_num(\@ttls);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
    }


    my $gap_threshold = 5;
    $heuristic = "gap_ttl_num.gap$gap_threshold";
    print "  $heuristic\n" if($DEBUG0);
    $if_tether = Tethering::check_gap_ttl_num(\@ttls, $gap_threshold);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
    }


    #############
    ## Check TCP Timestamp continuity
    #############
    my @tx_times;
    my @rx_times;
    foreach my $this_rx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{ALL_FLOW}{RX_TIME} })) {
        push(@rx_times, $this_rx_time);
        push(@tx_times, $ip_info{IP}{$this_ip}{ALL_FLOW}{RX_TIME}{$this_rx_time}{TX_TIME});
    }

    my @freq_threshs   =     (1000, 2000, 9999999, 9999999);
    my @tolerate_wraps =     (1,    1,    0,       1);
    my @tolerate_disorders = (1,    0,    0,       0);
    my @tolerate_gaps =      (1,    5,    0,       0);
    foreach my $ind (0 .. scalar(@freq_threshs)-1) {
        my $freq_thresh       = $freq_threshs[$ind];
        my $tolerate_wrap     = $tolerate_wraps[$ind];
        my $tolerate_disorder = $tolerate_disorders[$ind];
        my $tolerate_gap      = $tolerate_gaps[$ind];

        $heuristic = "ts_continuity.freq$freq_thresh.wrap$tolerate_wrap.disorder$tolerate_disorder.gap$tolerate_gap";
        print "  $heuristic\n" if($DEBUG0);
        $if_tether = Tethering::check_timestamp_continuity(\@rx_times, \@tx_times, $freq_thresh, $tolerate_wrap, $tolerate_disorder, $tolerate_gap);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
    }


    #############
    ## Check clock frequency Heuristic
    #############
    my $flows_ref = \%{ $ip_info{IP}{$this_ip} };
    my @freqs = (2, 10, 100, 200, 250, 1000);
    
    ## 1.
    my @freq_span_thresholds = (1, 10, 50);
    foreach my $freq_span_threshold (@freq_span_thresholds) {
        $heuristic = "freq_first_last_span.span$freq_span_threshold";
        print "  $heuristic\n" if($DEBUG0);
        my $if_tether = Tethering::check_flow_frequency_first_last_span($flows_ref, $freq_span_threshold);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
    }

    
    ## 2.
    $heuristic = "freq_first_last_enu";
    print "  $heuristic\n" if($DEBUG0);
    $if_tether = Tethering::check_flow_frequency_first_last_enumeration($flows_ref, \@freqs);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
    }


    ## 3. 
    @freq_span_thresholds = (1, 10, 50);
    my @rx_time_gaps      = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        foreach my $freq_span_threshold (@freq_span_thresholds) {
            $heuristic = "freq_median_span.span$freq_span_threshold.rx_gap$rx_time_gap";
            print "  $heuristic\n" if($DEBUG0);
            my $if_tether = Tethering::check_flow_frequency_median_span($flows_ref, $rx_time_gap, $freq_span_threshold);

            if($if_tether >= 1) {
                $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            }
            else {
                $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            }
        }
    }


    ## 4.
    @rx_time_gaps = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        $heuristic = "freq_median_enu.rx_gap$rx_time_gap";
        print "  $heuristic\n" if($DEBUG0);
        my $if_tether = Tethering::check_flow_frequency_median_enumeration($flows_ref, \@freqs, $rx_time_gap);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
    }


    ## 5. 
    my @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "freq_enu_boot.boot_span$boot_time_span_thresh";
        print "  $heuristic\n" if($DEBUG0);
        my $if_tether = Tethering::check_flow_frequency_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
    }


    #############
    ## Check boot time Heuristic
    #############
    ## 1.
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_first_last_span.span$boot_time_span_thresh";
        print "  $heuristic\n" if($DEBUG0);

        my $if_tether = Tethering::check_boot_time_first_last_span($flows_ref, $boot_time_span_thresh);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
    }

    
    ## 2.
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_first_last_enu.span$boot_time_span_thresh";
        print "  $heuristic\n" if($DEBUG0);
        $if_tether = Tethering::check_boot_time_first_last_enumeration($flows_ref, \@freqs, $boot_time_span_thresh);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
    }


    ## 3. 
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    @rx_time_gaps           = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
            $heuristic = "boot_time_median_span.span$boot_time_span_thresh.rx_gap$rx_time_gap";
            print "  $heuristic\n" if($DEBUG0);
            my $if_tether = Tethering::check_boot_time_median_span($flows_ref, $rx_time_gap, $boot_time_span_thresh);

            if($if_tether >= 1) {
                $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            }
            else {
                $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            }
        }
    }


    ## 4.
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    @rx_time_gaps           = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
            $heuristic = "boot_time_median_enu.span$boot_time_span_thresh.rx_gap$rx_time_gap";
            print "  $heuristic\n" if($DEBUG0);
            my $if_tether = Tethering::check_boot_time_median_enumeration($flows_ref, \@freqs, $rx_time_gap, $boot_time_span_thresh);

            if($if_tether >= 1) {
                $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            }
            else {
                $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            }
        }
    }


    ## 5. 
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_enu.span$boot_time_span_thresh";
        print "  $heuristic\n" if($DEBUG0);
        my $if_tether = Tethering::check_boot_time_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
    }
}



#############
## Print out detection results
#############
print "Print out detection results\n" if($DEBUG2);
foreach my $this_heuristic (keys %{ $tethered_ips{HEURISTIC} }) {
    print "  - $this_heuristic: ".scalar(keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} }))."\n" if($DEBUG2 or $DEBUG3);

    ## Tethered IPs
    open FH, "> $output_dir/$file_name.$this_heuristic.txt" or die $!;
    print FH join("\n", (keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n";
    print join("\n", (keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n" if($DEBUG1);
    close FH;

    ## Non-tethered IPs
    open FH, "> $output_dir/$file_name.$this_heuristic.nontether.txt" or die $!;
    print FH join("\n", (keys (%{ $non_tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n";
    close FH;
}




