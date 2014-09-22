#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.15 @ UT Austin
##
## - input: 
##    
##
##  e.g.
##    perl detect.sim.pl sim.i5.a5.w5.s1.dup1.host0.2.bt86400.s1
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use lib "../utils";

use Tethering;
use IPTool;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 0;
my $DEBUG2 = 1;     ## program flow
my $DEBUG3 = 1;     ## results
my $DEBUG4 = 1;     ## each heuristic
my $DEBUG5 = 0;     ## os file


#############
# Constants
#############
my $MIN_NUM_PKTS = 0;


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_sim_trace/gen_trace";
my $output_dir = "../processed_data/subtask_sim_trace/detection";
# my $tmp_dir = "../processed_data/subtask_detect/tmp";

my $filename;
my $gt_filename;

my %ip_info = ();
my %gt_info = ();
my %detected_ips = ();
my $heuristic;


#############
# check input
#############
print "check input\n" if($DEBUG2);
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$filename = $ARGV[0];
$gt_filename = "$filename.gt";


#############
## Read ground truth
#############
print "Read ground truth\n" if($DEBUG2);

open FH_GT, "bzcat $input_dir/$gt_filename.txt.bz2 |" or die $!;
while(<FH_GT>) {
    if($_ =~ /(.*), (\d), (.*), (.*), (.*)\n/) {
        my $ip = $1;
        my $gt = $2 + 0;
        my $orig_ip = $3; ## some are duplicate
        my $dup_ip = $4;
        my $dup_orig_ip = $5;

        if($gt == 0) {
            # $gt_info{NORMAL}{$ip} = 1;
            $gt_info{NORMAL}{$ip}{ORIG_IP} = $orig_ip;
        }
        else {
            # $gt_info{HOST}{$ip} = 1;
            $gt_info{HOST}{$ip}{ORIG_IP} = $orig_ip;
            $gt_info{HOST}{$ip}{DUP_IP} = $dup_ip;
            $gt_info{HOST}{$ip}{DUP_ORIG_IP} = $dup_orig_ip;
        }
    }
}
close FH_GT;

print "  # host  : ".scalar(keys %{ $gt_info{HOST} })."\n";
print "  # normal: ".scalar(keys %{ $gt_info{NORMAL} })."\n";



#############
## read input files
#############
print "start to read input files\n" if($DEBUG2);

open FH, "bzcat $input_dir/$filename.txt.bz2 | " or die $!;
while(<FH>) {
    chomp;
    print $_."\n" if($DEBUG0);

    my ($cnt, $rcv_time, $src_list, $dst_list, $sport_list, $dport_list, $id_list, $ttl_list, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $_);
    my @tmp = split(/,/, $src_list); my $src = $tmp[-1];
    @tmp = split(/,/, $dst_list); my $dst = $tmp[-1];
    @tmp = split(/,/, $sport_list); my $sport = $tmp[-1];
    @tmp = split(/,/, $dport_list); my $dport = $tmp[-1];
    @tmp = split(/,/, $id_list); my $id = $tmp[-1];
    @tmp = split(/,/, $ttl_list); my $ttl = $tmp[-1];
    $cnt += 0; $rcv_time += 0; $id += 0; $ttl += 0; $tsval += 0; $tsecr += 0; $wsscale += 0; $inflight += 0;
    print "  src=$src, dst=$dst, id=$id, ttl=$ttl, ts=$tsval, win scale=$wsscale, opt=$opt_kind, UA=$ua, flight bytes=$inflight\n" if($DEBUG0);


    $ip_info{SRC}{$src}{ALL_FLOW}{TTL}{$ttl} = 1;
    $ip_info{SRC}{$src}{ALL_FLOW}{UA}{$ua} = 1 if($ua != "");

    if($tsval != 0) {
        push( @{ $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{TX_TIME} }, $tsval);
        push( @{ $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{RX_TIME} }, $rcv_time);
    
        # $ip_info{SRC}{$src}{ALL_FLOW}{RCV_TIME}{$rcv_time}{TX_TIME} = $tsval;
        push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{TX_TIME} }, $tsval);
        push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{RX_TIME} }, $rcv_time);
    }

    if($id != 0) {
        push( @{ $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{IP_ID} }, $id);
        push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{IP_ID} }, $id);
    }

    if($wsscale > 0) {
        $ip_info{SRC}{$src}{ALL_FLOW}{WSSCALE}{$wsscale} = 1;
    }

    if($opt_kind ne "") {
        my @kinds = split(/,/, $opt_kind);
        foreach my $kind (@kinds) {
            $kind += 0;
            $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND}{$kind} ++;
            $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{OPT_KIND}{$kind} ++;
        }
        $ip_info{SRC}{$src}{ALL_FLOW}{NUM_OPT_KIND}{scalar(@kinds)} ++;
    }
    else {
        $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND}{-1} ++;
        $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{OPT_KIND}{-1} ++;
        $ip_info{SRC}{$src}{ALL_FLOW}{NUM_OPT_KIND}{0} ++;
    }

    if($inflight > 0) {
        push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{FLIGHT_RX_TIME} }, $rcv_time);
        push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{IN_FLIGHT} }     , $inflight);
    }
}


#############
## Check Heuristics
#############
print "Check Heuristics\n" if($DEBUG2);

foreach my $this_ip (keys %{ $ip_info{SRC} }) {
    if($DEBUG4) {
        print "\n  - $this_ip";
        if(exists $gt_info{HOST}{$this_ip}) {
            print "(Tethering!! ".$gt_info{HOST}{$this_ip}{ORIG_IP}.")\n";
            print "    tether IP=".$gt_info{HOST}{$this_ip}{DUP_IP}." (".$gt_info{HOST}{$this_ip}{DUP_ORIG_IP}.")\n";
        }
        else {
            print "(".$gt_info{NORMAL}{$this_ip}{ORIG_IP}.")\n";
        }
        print "\n";
    }

    my $cnt_heuristics = 0;
    my $cnt_detect = 0;


    #############
    ## Check TTL Heuristic
    #############
    my @ttls = (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{TTL} });
    
    $heuristic = "ttl_num";
    $cnt_heuristics ++;
    my $if_tether = Tethering::check_ttl_num(\@ttls);
    print "    $heuristic: $if_tether (".join(",", @ttls).")\n" if($DEBUG4);

    if($if_tether >= 1) {
        $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
        $cnt_detect ++;
    }
    else {
        $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    }

    my @gap_thresholds = (1..5);
    foreach my $gap_threshold (@gap_thresholds) {
        $heuristic = "gap_ttl_num.gap$gap_threshold";
        $cnt_heuristics ++;
        $if_tether = Tethering::check_gap_ttl_num(\@ttls, $gap_threshold);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }


    #############
    ## Check TCP Timestamp monotonicity
    #############
    my @tx_times = ();
    my @rx_times = ();
    if(exists $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME}) {
        foreach my $ti (0 .. scalar(@{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME} })-1) {
            push(@rx_times, ${ $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME} }[$ti]);
            push(@tx_times, ${ $ip_info{SRC}{$this_ip}{ALL_FLOW}{TX_TIME} }[$ti]);
        }
    }
    # print "      size of rx=".scalar(@rx_times).", tx=".scalar(@tx_times)."\n";

    my @freq_threshs   =     (2000, 9999999, 9999999);
    my @tolerate_wraps =     (1,    0,       1);
    my @tolerate_disorders = (0,    0,       0);
    my @tolerate_gaps =      (5,    0,       0);
    foreach my $ind (0 .. scalar(@freq_threshs)-1) {
        my $freq_thresh       = $freq_threshs[$ind];
        my $tolerate_wrap     = $tolerate_wraps[$ind];
        my $tolerate_disorder = $tolerate_disorders[$ind];
        my $tolerate_gap      = $tolerate_gaps[$ind];

        $heuristic = "ts_monotonicity.freq$freq_thresh.wrap$tolerate_wrap.disorder$tolerate_disorder.gap$tolerate_gap";
        $cnt_heuristics ++;
        $if_tether = Tethering::check_timestamp_monotonicity(\@rx_times, \@tx_times, $freq_thresh, $tolerate_wrap, $tolerate_disorder, $tolerate_gap);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }


        # if($DEBUG4) {
        #     open FH_TMP, "> $tmp_dir/$this_ip.$heuristic.txt" or die $!;
        #     foreach my $i (0 .. @rx_times-1) {
        #         print FH_TMP "".$rx_times[$i].", ".$tx_times[$i]."\n";
        #     }
        #     close FH_TMP;
        # }
    }


    #############
    ## Check Window Scale
    #############
    my %os = ();
    %{ $os{ALL} } = ();

    $heuristic = "win_scale";
    $cnt_heuristics ++;
    my $win_scales_ref = \%{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE} };
    my ($if_tether, $tmp_os_ref) = Tethering::check_win_scale($win_scales_ref);
    my %tmp = (%{ $os{ALL} }, %$tmp_os_ref);
    %{ $os{ALL} } = %tmp;
    %{ $os{HEURISTIC}{$heuristic} } = %$tmp_os_ref;

    print "    $heuristic: $if_tether (".join(",", (keys %{ $os{HEURISTIC}{$heuristic} })).")\n" if($DEBUG4);

    if($if_tether >= 1) {
        $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
        $cnt_detect ++;
        # print ", 1" if($DEBUG3);
        # print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
        # print ", 0" if($DEBUG3);
        # print FH_OUT ", 0" if($DEBUG3);
    }


    #############
    ## Check TCP Timestamp Option (kind = 8)
    ##   $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND}{$kind} 
    #############
    my $opt_kind_ref = \%{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND} };
    my $opt_kind_flow_erf = \%{ $ip_info{SRC}{$this_ip} };

    my @all_flow_threshs = (0.05, 0.2, 0.1, 0.2, 0.3);
    my @per_flow_threshs = (0.05, 0.1, 0.1, 0.2, 0.3);

    foreach my $ti (0 .. @all_flow_threshs-1) {
        my $all_flow_thresh = $all_flow_threshs[$ti];
        my $per_flow_thresh = $per_flow_threshs[$ti];

        $heuristic = "ts_option.all$all_flow_thresh.per$per_flow_thresh";
        $cnt_heuristics ++;

        my $tmp_os_ref = Tethering::check_tcp_timestamp_option($opt_kind_ref, $opt_kind_flow_erf, $all_flow_thresh, $per_flow_thresh);
        my %tmp = (%{ $os{ALL} }, %$tmp_os_ref);
        %{ $os{ALL} } = %tmp;
        %{ $os{HEURISTIC}{$heuristic} } = %$tmp_os_ref;

        my $if_tether = 0;
        $if_tether = 1 if(scalar(keys %{ $os{HEURISTIC}{$heuristic} }) > 1);
        print "    $heuristic: $if_tether (".join(",", (keys %{ $os{HEURISTIC}{$heuristic} })).")\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }


    #############
    ## Check IP ID monotonicity
    #############
    my @ip_ids = ();
    my $ip_ids_flow_ref = \%{ $ip_info{SRC}{$this_ip} };

    if(exists $ip_info{SRC}{$this_ip}{ALL_FLOW}{IP_ID}) {
        @ip_ids = @{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{IP_ID} };
    }
    else {
        @ip_ids = (0);
    }

    
    $heuristic = "ip_id_monotonicity";
    $cnt_heuristics ++;
    my $tmp_os_ref = Tethering::check_ip_id_monotonicity(\@ip_ids, $ip_ids_flow_ref);
    my %tmp = (%{ $os{ALL} }, %$tmp_os_ref);
    %{ $os{ALL} } = %tmp;
    %{ $os{HEURISTIC}{$heuristic} } = %$tmp_os_ref;
    my $if_tether = 0;
    $if_tether = 1 if(scalar(keys %{ $os{HEURISTIC}{$heuristic} }) > 1);
    print "    $heuristic: $if_tether (".join(",", (keys %{ $os{HEURISTIC}{$heuristic} })).")\n" if($DEBUG4);

    if($if_tether >= 1) {
        $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
        $cnt_detect ++;
        # print ", 1" if($DEBUG3);
        # print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
        # print ", 0" if($DEBUG3);
        # print FH_OUT ", 0" if($DEBUG3);
    }
    
    # if($DEBUG4) {
    #     open FH_TMP, "> $tmp_dir/$this_ip.$heuristic.txt" or die $!;
    #     print FH_TMP "".join("\n", @ip_ids)."\n";
    #     close FH_TMP;
    # }


    #############
    ## Check clock frequency Heuristic
    #############
    my $flows_ref = \%{ $ip_info{SRC}{$this_ip} };
    my @freqs = (2, 10, 100, 200, 250, 1000);
    
    ## 1.
    my @freq_span_thresholds = (1, 10, 50);
    foreach my $freq_span_threshold (@freq_span_thresholds) {
        $heuristic = "freq_first_last_span.span$freq_span_threshold";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_flow_frequency_first_last_span($flows_ref, $freq_span_threshold);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }

    
    ## 2.
    $heuristic = "freq_first_last_enu";
    $cnt_heuristics ++;
    $if_tether = Tethering::check_flow_frequency_first_last_enumeration($flows_ref, \@freqs);
    print "    $heuristic: $if_tether\n" if($DEBUG4);

    if($if_tether >= 1) {
        $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
        $cnt_detect ++;
        # print ", 1" if($DEBUG3);
        # print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
        # print ", 0" if($DEBUG3);
        # print FH_OUT ", 0" if($DEBUG3);
    }


    ## 3. 
    @freq_span_thresholds = (1, 10, 50);
    my @rx_time_gaps      = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        foreach my $freq_span_threshold (@freq_span_thresholds) {
            $heuristic = "freq_median_span.span$freq_span_threshold.rx_gap$rx_time_gap";
            $cnt_heuristics ++;
            my $if_tether = Tethering::check_flow_frequency_median_span($flows_ref, $rx_time_gap, $freq_span_threshold);
            print "    $heuristic: $if_tether\n" if($DEBUG4);

            if($if_tether >= 1) {
                $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
                $cnt_detect ++;
                # print ", 1" if($DEBUG3);
                # print FH_OUT ", 1" if($DEBUG3);
            }
            else {
                $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
                # print ", 0" if($DEBUG3);
                # print FH_OUT ", 0" if($DEBUG3);
            }
        }
    }


    ## 4.
    @rx_time_gaps = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        $heuristic = "freq_median_enu.rx_gap$rx_time_gap";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_flow_frequency_median_enumeration($flows_ref, \@freqs, $rx_time_gap);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }


    ## 5. 
    my @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "freq_enu_boot.boot_span$boot_time_span_thresh";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_flow_frequency_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }


    ############
    # Check boot time Heuristic
    ############
    ## 1.
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_first_last_span.span$boot_time_span_thresh";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_boot_time_first_last_span($flows_ref, $boot_time_span_thresh);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }

    
    ## 2.
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_first_last_enu.span$boot_time_span_thresh";
        $cnt_heuristics ++;
        $if_tether = Tethering::check_boot_time_first_last_enumeration($flows_ref, \@freqs, $boot_time_span_thresh);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }


    ## 3. 
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    @rx_time_gaps           = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
            $heuristic = "boot_time_median_span.span$boot_time_span_thresh.rx_gap$rx_time_gap";
            $cnt_heuristics ++;
            my $if_tether = Tethering::check_boot_time_median_span($flows_ref, $rx_time_gap, $boot_time_span_thresh);
            print "    $heuristic: $if_tether\n" if($DEBUG4);

            if($if_tether >= 1) {
                $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
                $cnt_detect ++;
                # print ", 1" if($DEBUG3);
                # print FH_OUT ", 1" if($DEBUG3);
            }
            else {
                $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
                # print ", 0" if($DEBUG3);
                # print FH_OUT ", 0" if($DEBUG3);
            }
        }
    }


    ## 4.
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    @rx_time_gaps           = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
            $heuristic = "boot_time_median_enu.span$boot_time_span_thresh.rx_gap$rx_time_gap";
            $cnt_heuristics ++;
            my $if_tether = Tethering::check_boot_time_median_enumeration($flows_ref, \@freqs, $rx_time_gap, $boot_time_span_thresh);
            print "    $heuristic: $if_tether\n" if($DEBUG4);

            if($if_tether >= 1) {
                $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
                $cnt_detect ++;
                # print ", 1" if($DEBUG3);
                # print FH_OUT ", 1" if($DEBUG3);
            }
            else {
                $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
                # print ", 0" if($DEBUG3);
                # print FH_OUT ", 0" if($DEBUG3);
            }
        }
    }


    ## 5. 
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_enu.span$boot_time_span_thresh";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_boot_time_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);
        print "    $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
            $cnt_detect ++;
            # print ", 1" if($DEBUG3);
            # print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
            # print ", 0" if($DEBUG3);
            # print FH_OUT ", 0" if($DEBUG3);
        }
    }

    # print "$this_ip, $cnt_detect, $cnt_heuristics\n" if($DEBUG3);
    # print ", ".$os_info{$this_ip}.":".join(", ", (keys %os))."\n" if($DEBUG3);
    # print ", ".join(", ", (keys %os))."\n" if($DEBUG3);
    # print FH_OUT ", ".join(", ", (keys %os))."\n" if($DEBUG3);

}


#############
## Check ground truth
#############
print "Check ground truth\n" if($DEBUG2);

foreach my $this_h (sort { $a cmp $b } (keys %{ $detected_ips{HEURISTIC} })) {
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;
    foreach my $this_ip (keys %{ $detected_ips{HEURISTIC}{$this_h}{HOST_IP} }) {
        if(exists $gt_info{HOST}{$this_ip}) {
            $tp ++;
        }
        elsif(exists $gt_info{NORMAL}{$this_ip}) {
            $fp ++;
        }
        else {
            die "known IP: $this_ip\n";
        }
    }
    foreach my $this_ip (keys %{ $detected_ips{HEURISTIC}{$this_h}{NORMAL_IP} }) {
        if(exists $gt_info{HOST}{$this_ip}) {
            $fn ++;
        }
        elsif(exists $gt_info{NORMAL}{$this_ip}) {
            $tn ++;
        }
        else {
            die "known IP: $this_ip\n";
        }
    }
    my $prec = 1;
    $prec = $tp / ($tp + $fp) if($tp + $fp > 0);
    my $recall = 1;
    $recall = $tp / ($tp + $fn) if($tp + $fn > 0);
    

    print "  $this_h: prec=$prec, recall=$recall (TP=$tp, TN=$tn, FP=$fp, FN=$fn)\n";
}

#     # print "\n  - $this_ip (".$os_info{$this_ip}.")\n" if($DEBUG4);
#     print "\n  - $this_ip\n" if($DEBUG4);
#     print "$this_ip" if($DEBUG3);
#     print FH_OUT "$this_ip" if($DEBUG3);
#     my $cnt_heuristics = 0;
#     my $cnt_detect = 0;



    

#     




# close FH_OUT;


# #############
# ## Print out detection results
# #############
# print "\nPrint out tethering results\n" if($DEBUG2);

# foreach my $this_heuristic (sort {$a cmp $b} (keys %{ $tethered_ips{HEURISTIC} })) {
#     print "  - $this_heuristic: ".scalar(keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} }))."\n" if($DEBUG2);

#     ## Tethered IPs
#     # open FH, "> $output_dir/$file_name.$this_heuristic.txt" or die $!;
#     # print FH join("\n", (keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n";
#     # print join("\n", (keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n" if($DEBUG1);
#     # close FH;
# }

# print "Print out non-tethering results\n" if($DEBUG2);
# foreach my $this_heuristic (sort {$a cmp $b} (keys %{ $non_tethered_ips{HEURISTIC} })) {
#     print "  - $this_heuristic: ".scalar(keys (%{ $non_tethered_ips{HEURISTIC}{$this_heuristic}{IP} }))."\n" if($DEBUG2);

#     ## Non-tethered IPs
#     # open FH, "> $output_dir/$file_name.$this_heuristic.nontether.txt" or die $!;
#     # print FH join("\n", (keys (%{ $non_tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n";
#     # close FH;
# }

