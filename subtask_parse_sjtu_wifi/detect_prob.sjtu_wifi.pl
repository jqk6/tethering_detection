#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.15 @ UT Austin
##
## - input: 
##    
##
##  e.g.
##    perl detect_prob.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.2.bt0.s1 sjtu_wifi.filter.dup1.host0.2.bt0.s1
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use lib "../utils";

use Tethering;
use TetheringFeatures;
use IPTool;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 0;
my $DEBUG2 = 1;     ## program flow
my $DEBUG3 = 1;     ## results
my $DEBUG4 = 1;     ## each heuristic
my $DEBUG5 = 0;     ## results: gt, prob
my $DEBUG6 = 1;     ## results: precision, recall
my $DEBUG7 = 1;     ## results: detailed features

#############
# Constants
#############
my $MIN_NUM_PKTS = 0;
my $PR_TETHERING = 0.2;


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_parse_sjtu_wifi/gen_trace";
my $input_dir_prob  = "../processed_data/subtask_parse_sjtu_wifi/prob";
my $output_dir = "../processed_data/subtask_parse_sjtu_wifi/detect";

my $filename;
my $gt_filename;
my $prob_filename;
my $output_filename;

my %ip_info = ();
my %gt_info = ();
my %prob_info = ();
my %detected_ips = ();
my %feature_info = ();
my %os_feature_info = ();
my $heuristic;

my %tethering_features = ();
# $tethering_features{"boot_time_first_last_stdev.thresh800000.diff"} = 1;
# $tethering_features{"boot_time_first_last_stdev.thresh800000.same"} = 1;
# $tethering_features{"freq_first_last_span.thresh10.diff"} = 1;
# $tethering_features{"freq_first_last_span.thresh10.same"} = 1;
# $tethering_features{"id_monotonic_pkts"} = 1;
# $tethering_features{"ts_monotonic"} = 1;
$tethering_features{"ttl_num.gap_4==1"} = 1;
$tethering_features{"ttl_num.gap_4>1"} = 1;
##
# $tethering_features{"freq_stable"} = 1;
# $tethering_features{"freq_unstable"} = 1;
# $tethering_features{"id_monotonic_flows"} = 1;
# $tethering_features{"id_monotonic_partial"} = 1;
# $tethering_features{"id_random"} = 1;
# $tethering_features{"tcp_ts_opt_high"} = 1;
# $tethering_features{"tcp_ts_opt_low"} = 1;


#############
# check input
#############
print "check input\n" if($DEBUG2);
if(@ARGV != 2) {
    print "wrong number of input\n";
    exit;
}
$filename = $ARGV[0];
$prob_filename = $ARGV[1].".feature";
$gt_filename = "$filename.gt";
$output_filename = "$filename.prob";

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

my $num_host = scalar(keys %{ $gt_info{HOST} });
my $num_normal = scalar(keys %{ $gt_info{NORMAL} });
my $num_ip = $num_normal + $num_host;
print "  # host  : $num_host\n";
print "  # normal: $num_normal\n";



#############
## Read probability
#############
print "Read probability\n" if($DEBUG2);

my $type;
    
open FH_PR, "$input_dir_prob/$prob_filename.txt" or die $!;
while(<FH_PR>) {
    chomp;

    if($_ =~ /^TYPE: (\w+)$/) {
        $type = $1;
        print "  $type\n";

        if($type ne "tethering") {
            ## OS features
            my $line = <FH_PR>;
            my ($tmp, $pr_os) = split(",", $line);
            $pr_os += 0;

            print "    Pr(OS) = $pr_os\n";
            $prob_info{TYPE}{$type}{PR_OS} = $pr_os;
        }
        next;
    }
    
    my ($feature, $pr_f_tether, $pr_f, $pr_tether_f) = split(",", $_);
    next if($type eq "tethering" and !(exists $tethering_features{$feature}));
    $pr_f_tether += 0; $pr_f += 0; $pr_tether_f += 0;

    print "    $feature ($type): Pr(f|tether)=$pr_f_tether, Pr(f)=$pr_f, Pr(tether|f)=$pr_tether_f\n";

    $prob_info{TYPE}{$type}{FEATURE}{$feature}{PR_F_TETHER} = $pr_f_tether;
    $prob_info{TYPE}{$type}{FEATURE}{$feature}{PR_F} = $pr_f;
}
close FH_PR;


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
    $ip_info{SRC}{$src}{ALL_FLOW}{UA}{$ua} = 1 if($ua ne "");

    if($tsval != 0) {
        push( @{ $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{TX_TIME} }, $tsval);
        push( @{ $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{RX_TIME} }, $rcv_time);
    
        $ip_info{SRC}{$src}{ALL_FLOW}{RX_TIME}{$rcv_time}{TX_TIME} = $tsval;
        # push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{TX_TIME} }, $tsval);
        # push( @{ $ip_info{SRC}{$src}{ALL_FLOW}{RX_TIME} }, $rcv_time);
    }

    if($id != 0) {
        die "id < 0\n" if($id < 0);
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
    my $has_feature;
    my $this_os = "";


    #############
    ## Identify OS by User Agent
    #############
    $heuristic = "user_agent";
    $cnt_heuristics ++;
    my @ua = keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{UA} };
    my @ua_os = Tethering::identify_os(\@ua);

    if(scalar(@ua_os) == 0) {
        ## no OS detected
        my $feature = "no_user_agent";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif(scalar(@ua_os) == 1) {
        ## detect 1 OS
        my $feature = "user_agent_os==1";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        ## for OS features
        $this_os = $ua_os[0];
        # if(exists $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{SRC}{$this_ip} = 1;
        #     $os_feature_info{OS}{$this_os}{CNT} ++;
        # }

        # $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif(scalar(@ua_os) > 1) {
        ## detect 1 OS
        my $feature = "user_agent_os>1";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    
    
    #############
    ## Check TTL features
    ## 1. ttl_num>1
    ## 2. ttl_num==1
    #############
    my @ttls = (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{TTL} });
    
    # $heuristic = "ttl_num";
    # $cnt_heuristics ++;
    # $has_feature = TetheringFeatures::ttl_num_feature(\@ttls);
    # print "    $heuristic: $has_feature\n" if($DEBUG4);

    # if($has_feature) {
    #     ## 1. ttl_num>1
    #     my $feature = "ttl_num>1";
    #     $feature_info{FEATURE}{$feature}{CNT} ++;
    #     $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});
    # }
    # else {
    #     ## 2. ttl_num==1
    #     my $feature = "ttl_num==1";
    #     $feature_info{FEATURE}{$feature}{CNT} ++;
    #     $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});
    # }
    
    
    #############
    ## Check TTL-gap features
    ## 1. ttl_num.gap_n>1
    ## 2. ttl_num.gap_n==1
    #############
    my @gap_thresholds = (4);
    foreach my $gap_threshold (@gap_thresholds) {
        $heuristic = "gap_ttl_num.gap$gap_threshold";
        $cnt_heuristics ++;
        $has_feature = TetheringFeatures::ttl_num_gap_feature(\@ttls, $gap_threshold);
        print "    $heuristic: $has_feature\n" if($DEBUG4);

        if($has_feature) {
            ## 1. ttl_num.gap_n>1
            my $feature = "ttl_num.gap_$gap_threshold>1";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        else {
            ## 2. ttl_num.gap_n==1
            my $feature = "ttl_num.gap_$gap_threshold==1";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
    }



    #############
    ## Check IP ID monotonicity
    ## 1. monotonic for all pkts
    ## 2. monotonic for each flows
    ## 3. monotonic for part of flows
    ## 4. not monotonic
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
    my $has_feature = TetheringFeatures::ip_id_monotonicity_feature(\@ip_ids, $ip_ids_flow_ref);
    print "    $heuristic: $has_feature\n" if($DEBUG4);
    
    if($has_feature < 0) {
        ## not enough packets having IP ID
        my $feature = "id_not_enough_pkts";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 0) {
        ## 1. monotonic for all pkts
        my $feature = "id_monotonic_pkts";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 1) {
        ## 2. monotonic for each flows
        my $feature = "id_monotonic_flows";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 2) {
        ## 3. monotonic for part of flows
        my $feature = "id_monotonic_partial";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 3) {
        ## 4. not monotonic
        my $feature = "id_random";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    else {
        die "IP ID: $has_feature\n";
    }


    #############
    ## Check Window Scale
    ## 1. iOS
    ## 2. Android
    ## 3. Windows
    #############
    $heuristic = "win_scale";
    $cnt_heuristics ++;
    
    my $win_scales_ref = \%{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE} };
    $has_feature = TetheringFeatures::win_scale_feature($win_scales_ref);

    print "    $heuristic: $has_feature\n" if($DEBUG4);

    if($has_feature < 0) {
        ## unknown scale
    }
    elsif($has_feature == 0) {
        ## 1. iOS
        my $feature = "wsf_ios";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 1) {
        ## 2. Android
        my $feature = "wsf_android";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 2) {
        ## 3. Windows
        my $feature = "wsf_windows";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    else {
        die "WSF: $has_feature\n";
    }


    #############
    ## Check TCP Timestamp Option (kind = 8)
    ## 1. ratio of packets with TCP TS is high
    ## 2. ratio of packets with TCP TS is low: Windows
    #############
    my $opt_kind_ref = \%{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND} };
    my $opt_kind_flow_ref = \%{ $ip_info{SRC}{$this_ip} };

    my @per_flow_threshs = (0.3);

    foreach my $ti (0 .. @per_flow_threshs-1) {
        my $per_flow_thresh = $per_flow_threshs[$ti];

        $heuristic = "ts_option.per$per_flow_thresh";
        $cnt_heuristics ++;

        my $has_feature = TetheringFeatures::tcp_timestamp_option_feature($opt_kind_ref, $opt_kind_flow_ref, $per_flow_thresh);
        print "    $heuristic: $has_feature\n" if($DEBUG4);

        if($has_feature == 0) {
            ## 2. ratio of packets with TCP TS is low
            my $feature = "tcp_ts_opt_low";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        elsif($has_feature == 1) {
            ## 1. ratio of packets with TCP TS is high
            my $feature = "tcp_ts_opt_high";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
    }


    #############
    ## Check TCP Timestamp monotonicity
    ## 1. TS is monotonic and no large gap
    ## 2. TS is not monotonic
    ## 3. TS is monotonic but has large gap
    #############
    my @tx_times = ();
    my @rx_times = ();
    if(exists $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME}) {
        # foreach my $ti (0 .. scalar(@{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME} })-1) {
        #     push(@rx_times, ${ $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME} }[$ti]);
        #     push(@tx_times, ${ $ip_info{SRC}{$this_ip}{ALL_FLOW}{TX_TIME} }[$ti]);
        # }
        foreach my $this_rx_time (sort {$a <=> $b} (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME} })) {
            my $this_tx_time = $ip_info{SRC}{$this_ip}{ALL_FLOW}{RX_TIME}{$this_rx_time}{TX_TIME};
            push(@rx_times, $this_rx_time);
            push(@tx_times, $this_tx_time);
        }
    }
    # print "      size of rx=".scalar(@rx_times).", tx=".scalar(@tx_times)."\n";

    my $freq_thresh = 2000;

    $heuristic = "ts_monotonicity.freq$freq_thresh";
    $cnt_heuristics ++;
    $has_feature = TetheringFeatures::timestamp_monotonicity_feature(\@rx_times, \@tx_times, $freq_thresh);
    print "    $heuristic: $has_feature\n" if($DEBUG4);

    if($has_feature < 0) {
        ## not enough packet
        my $feature = "ts_not_enough_pkts";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 0) {
        ## 2. TS is not monotonic
        my $feature = "ts_not_monotonic";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 1) {
        ## 3. TS is monotonic but has large gap
        my $feature = "ts_large_gap";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 2) {
        ## 1. TS is monotonic and no large gap
        my $feature = "ts_monotonic";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }


    #############
    ## Check clock frequency stability Heuristic
    #############
    my $flows_ref = \%{ $ip_info{SRC}{$this_ip} };
    my @freqs = (2, 10, 100, 200, 250, 1000);
    
    $heuristic = "freq_stability";
    $cnt_heuristics ++;
    my $rx_time_gap = 0.5;
    my $has_feature = TetheringFeatures::flow_frequency_stable_feature($flows_ref, $rx_time_gap);
    print "    $heuristic: $has_feature\n" if($DEBUG4);

    if($has_feature < 0) {
        ## stable
        my $feature = "freq_no_flow";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 0) {
        ## stable
        my $feature = "freq_unstable";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    elsif($has_feature == 1) {
        ## stable
        my $feature = "freq_stable";
        # $feature_info{FEATURE}{$feature}{CNT} ++;
        # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

        # ## OS feature
        # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
        #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
        #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
        # }

        $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
    }
    

    #############
    ## Check clock frequency Heuristic
    #############
    ## 1.
    my @stdev_threshs = (10);
    foreach my $stdev_thresh (@stdev_threshs) {
        $heuristic = "freq_first_last_span.thresh$stdev_thresh";
        $cnt_heuristics ++;
        my $has_feature = TetheringFeatures::flow_frequency_first_last_stdev_feature($flows_ref, $stdev_thresh);
        print "    $heuristic: $has_feature\n" if($DEBUG4);

        if($has_feature < 0) {
            my $feature = "freq_first_last_span.thresh$stdev_thresh.not_enough_flow";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        elsif($has_feature == 0) {
            my $feature = "freq_first_last_span.thresh$stdev_thresh.same";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        elsif($has_feature == 1) {
            my $feature = "freq_first_last_span.thresh$stdev_thresh.diff";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        else {
            die "freq: $has_feature\n";
        }
    }
    
    
    # ## 2.
    # $heuristic = "freq_first_last_enu";
    # $cnt_heuristics ++;
    # my $num_freq = TetheringFeatures::flow_frequency_first_last_enumeration($flows_ref, \@freqs);
    # print "    $heuristic: #freq=$num_freq\n" if($DEBUG4);

    # # if($if_tether >= 1) {
    # #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    # #     $cnt_detect ++;
    # #     # print ", 1" if($DEBUG3);
    # #     # print FH_OUT ", 1" if($DEBUG3);
    # # }
    # # else {
    # #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    # #     # print ", 0" if($DEBUG3);
    # #     # print FH_OUT ", 0" if($DEBUG3);
    # # }
    # $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{VALUE} = $num_freq;
    # $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{TYPE} = "numeric";


    # ## 3. 
    # my @rx_time_gaps = (0);
    # foreach my $rx_time_gap (@rx_time_gaps) {
    #     $heuristic = "freq_median_span.rx_gap$rx_time_gap";
    #     $cnt_heuristics ++;
    #     my $span = TetheringFeatures::flow_frequency_median_span($flows_ref, $rx_time_gap);
    #     print "    $heuristic: span=$span\n" if($DEBUG4);

    #     # if($if_tether >= 1) {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    #     #     $cnt_detect ++;
    #     #     # print ", 1" if($DEBUG3);
    #     #     # print FH_OUT ", 1" if($DEBUG3);
    #     # }
    #     # else {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    #     #     # print ", 0" if($DEBUG3);
    #     #     # print FH_OUT ", 0" if($DEBUG3);
    #     # }
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{VALUE} = $span;
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{TYPE} = "numeric";
    # }


    # ## 4.
    # @rx_time_gaps = (0);
    # foreach my $rx_time_gap (@rx_time_gaps) {
    #     $heuristic = "freq_median_enu.rx_gap$rx_time_gap";
    #     $cnt_heuristics ++;
    #     my $num_freq = TetheringFeatures::flow_frequency_median_enumeration($flows_ref, \@freqs, $rx_time_gap);
    #     print "    $heuristic: #freq=$num_freq\n" if($DEBUG4);

    #     # if($if_tether >= 1) {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    #     #     $cnt_detect ++;
    #     #     # print ", 1" if($DEBUG3);
    #     #     # print FH_OUT ", 1" if($DEBUG3);
    #     # }
    #     # else {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    #     #     # print ", 0" if($DEBUG3);
    #     #     # print FH_OUT ", 0" if($DEBUG3);
    #     # }
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{VALUE} = $num_freq;
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{TYPE} = "numeric";
    # }


    # ## 5. 
    # my @boot_time_span_threshs = (100);
    # foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
    #     $heuristic = "freq_enu_boot.boot_span$boot_time_span_thresh";
    #     $cnt_heuristics ++;
    #     my $num_freq = TetheringFeatures::flow_frequency_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);
    #     print "    $heuristic: #freq=$num_freq\n" if($DEBUG4);

    #     # if($if_tether >= 1) {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    #     #     $cnt_detect ++;
    #     #     # print ", 1" if($DEBUG3);
    #     #     # print FH_OUT ", 1" if($DEBUG3);
    #     # }
    #     # else {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    #     #     # print ", 0" if($DEBUG3);
    #     #     # print FH_OUT ", 0" if($DEBUG3);
    #     # }
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{VALUE} = $num_freq;
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{TYPE} = "numeric";
    # }


    ############
    # Check boot time Heuristic
    ############
    ## 1.
    my @stdev_threshs = (800000);

    foreach my $stdev_thresh (@stdev_threshs) {
        $heuristic = "boot_time_first_last_stdev.thresh$stdev_thresh";
        $cnt_heuristics ++;
        my $has_feature = TetheringFeatures::boot_time_first_last_stdev_feature($flows_ref, $stdev_thresh);
        print "    $heuristic: $has_feature\n" if($DEBUG4);

        if($has_feature < 0) {
            my $feature = "boot_time_first_last_stdev.thresh$stdev_thresh.not_enough_flow";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        elsif($has_feature == 0) {
            my $feature = "boot_time_first_last_stdev.thresh$stdev_thresh.same";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }

            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        elsif($has_feature == 1) {
            my $feature = "boot_time_first_last_stdev.thresh$stdev_thresh.diff";
            # $feature_info{FEATURE}{$feature}{CNT} ++;
            # $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

            # ## OS feature
            # if($this_os ne "" and $gt_info{NORMAL}{$this_ip}) {
            #     $os_feature_info{FEATURE}{$feature}{CNT} ++;
            #     $os_feature_info{OS}{$this_os}{FEATURE}{$feature}{CNT} ++;
            # }
            $ip_info{SRC}{$this_ip}{FEATURE}{$feature} = 1;
        }
        else {
            die "boot time: $has_feature\n";
        }


    }
    
    
    # ## 2.
    # $heuristic = "boot_time_first_last_enu";
    # $cnt_heuristics ++;
    # my $span = TetheringFeatures::boot_time_first_last_enumeration($flows_ref, \@freqs);
    # print "    $heuristic: $span\n" if($DEBUG4);

    # # if($if_tether >= 1) {
    # #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    # #     $cnt_detect ++;
    # #     # print ", 1" if($DEBUG3);
    # #     # print FH_OUT ", 1" if($DEBUG3);
    # # }
    # # else {
    # #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    # #     # print ", 0" if($DEBUG3);
    # #     # print FH_OUT ", 0" if($DEBUG3);
    # # }
    # $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{VALUE} = $span;
    # $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{TYPE} = "numeric";
    

    # ## 3. 
    # my @rx_time_gaps = (0);
    # foreach my $rx_time_gap (@rx_time_gaps) {
    #     $heuristic = "boot_time_median_span.rx_gap$rx_time_gap";
    #     $cnt_heuristics ++;
    #     my $span = TetheringFeatures::boot_time_median_span($flows_ref, $rx_time_gap);
    #     print "    $heuristic: $span\n" if($DEBUG4);

    #     # if($if_tether >= 1) {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    #     #     $cnt_detect ++;
    #     #     # print ", 1" if($DEBUG3);
    #     #     # print FH_OUT ", 1" if($DEBUG3);
    #     # }
    #     # else {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    #     #     # print ", 0" if($DEBUG3);
    #     #     # print FH_OUT ", 0" if($DEBUG3);
    #     # }
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{VALUE} = $span;
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{TYPE} = "numeric";
    # }


    # ## 4.
    # @rx_time_gaps = (0);
    # foreach my $rx_time_gap (@rx_time_gaps) {
    #     $heuristic = "boot_time_median_enu.rx_gap$rx_time_gap";
    #     $cnt_heuristics ++;
    #     my $span = TetheringFeatures::boot_time_median_enumeration($flows_ref, \@freqs, $rx_time_gap);
    #     print "    $heuristic: $span\n" if($DEBUG4);

    #     # if($if_tether >= 1) {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    #     #     $cnt_detect ++;
    #     #     # print ", 1" if($DEBUG3);
    #     #     # print FH_OUT ", 1" if($DEBUG3);
    #     # }
    #     # else {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    #     #     # print ", 0" if($DEBUG3);
    #     #     # print FH_OUT ", 0" if($DEBUG3);
    #     # }
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{VALUE} = $span;
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"}{TYPE} = "numeric";
    # }


    ## 5. 
    # my @boot_time_span_threshs = (100);
    # foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
    #     $heuristic = "boot_time_enu.span$boot_time_span_thresh";
    #     $cnt_heuristics ++;
    #     my $span = TetheringFeatures::boot_time_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);
    #     print "    $heuristic: $span\n" if($DEBUG4);

    #     # if($if_tether >= 1) {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{HOST_IP}{$this_ip} = 1;
    #     #     $cnt_detect ++;
    #     #     # print ", 1" if($DEBUG3);
    #     #     # print FH_OUT ", 1" if($DEBUG3);
    #     # }
    #     # else {
    #     #     $detected_ips{HEURISTIC}{$heuristic}{NORMAL_IP}{$this_ip} = 1;
    #     #     # print ", 0" if($DEBUG3);
    #     #     # print FH_OUT ", 0" if($DEBUG3);
    #     # }
    #     $ip_info{SRC}{$this_ip}{HEURISTIC}{"$heuristic"} = $span;
    # }


    # print "$this_ip, $cnt_detect, $cnt_heuristics\n" if($DEBUG3);
    # print ", ".$os_info{$this_ip}.":".join(", ", (keys %os))."\n" if($DEBUG3);
    # print ", ".join(", ", (keys %os))."\n" if($DEBUG3);
    # print FH_OUT ", ".join(", ", (keys %os))."\n" if($DEBUG3);

}


#############
## Output features
#############
print "\nOutput features\n" if($DEBUG2);

# open FH_OUT, "> $output_dir/$output_filename" or die $!;
# print FH_OUT "tethering\n";



# close FH_OUT;

my @threshs = ();
for(my $i = 0; $i <= 1; $i += 0.001) {push(@threshs, $i);}
push(@threshs, 2);
# push(@threshs, 5);
# push(@threshs, 10);

my $best_prec = -1;
my $best_recall = -1;
my $best_f1 = -1;
my $best_thresh = -1;
foreach my $this_thresh (@threshs) {
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;
    foreach my $this_ip (keys %{ $ip_info{SRC} }) {
        # print "- $this_ip\n";
        # if(exists $gt_info{HOST}{$this_ip}) {
        #     print "(Tethering!! ".$gt_info{HOST}{$this_ip}{ORIG_IP}.")\n";
        #     print "    tether IP=".$gt_info{HOST}{$this_ip}{DUP_IP}." (".$gt_info{HOST}{$this_ip}{DUP_ORIG_IP}.")\n";
        # }
        if($DEBUG5) {
            print "$this_ip, ";
            if(exists $gt_info{HOST}{$this_ip}) { print "1, "; }
            else { print "0, "; }
        }
        
        ## Tethering
        my $numerator = 1;
        my $denominator = 1;
        foreach my $this_f (sort {$a cmp $b} (keys %{ $ip_info{SRC}{$this_ip}{FEATURE} })) {
            if(exists $prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}) {
                $numerator *= ($prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F_TETHER});
                $denominator *= $prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F};
            }
            else {
                # print "  $this_f: XXX - no such feature\n" if($DEBUG5);
            }
        }

        my $prob = $numerator * $PR_TETHERING / $denominator;
        # my $prob = $numerator / $denominator;
        # print "  prob = $prob\n";
        print "$prob\n" if($DEBUG5);

        if(exists $gt_info{HOST}{$this_ip} and $prob > $this_thresh) { 
            $tp ++; 
        }
        elsif(exists $gt_info{NORMAL}{$this_ip} and $prob <= $this_thresh) { 
            $tn ++; 
        }
        elsif(exists $gt_info{NORMAL}{$this_ip} and $prob > $this_thresh) { 
            $fp ++; 
        }
        elsif(exists $gt_info{HOST}{$this_ip} and $prob <= $this_thresh) { 
            $fn ++; 
        }
        else {die "wrong judgement\n";}
    }

    last if($tp + $fp == 0);
    my $prec = MyUtil::precision($tp, $fn, $fp, $tn);
    my $recall = MyUtil::recall($tp, $fn, $fp, $tn);
    my $f1 = MyUtil::f1_score($prec, $recall);

    if($f1 > $best_f1) {
        $best_f1 = $f1;
        $best_prec = $prec;
        $best_recall = $recall;
        $best_thresh = $this_thresh;
    }
    # print "  $this_thresh: f1=$f1 (prec=$prec, recall=$recall)\n" if($DEBUG6);
    print "$this_thresh $f1 $prec $recall\n" if($DEBUG6);
}

print "f1=$best_f1 (prec=$best_prec, recall=$best_recall, thresh=$best_thresh)\n" if($DEBUG6);


if($DEBUG7) {
    print "================================================\n";
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;
    my $this_thresh = $best_thresh;
    foreach my $this_ip (keys %{ $ip_info{SRC} }) {
        if($DEBUG7) {
            print "$this_ip"; 
            if(exists $gt_info{HOST}{$this_ip}) { 
                print " (".$gt_info{HOST}{$this_ip}{DUP_IP}.")\n"; 
            }
            else {
                print "\n";
            }
        }

        my $numerator = 1;
        my $denominator = 1;
        foreach my $this_f (sort {$a cmp $b} (keys %{ $ip_info{SRC}{$this_ip}{FEATURE} })) {
            if(exists $prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}) {
                if($DEBUG7) {
                    print "  $this_f: Pr(f|tether)=".$prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F_TETHER}.", Pr(f)=".$prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F}.", Pr(tether|f)=".($prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F_TETHER}*$PR_TETHERING/$prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F})."\n";
                }

                $numerator *= ($prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F_TETHER});
                $denominator *= $prob_info{TYPE}{"tethering"}{FEATURE}{$this_f}{PR_F};
            }
            else {
                print "  $this_f: XXX - no such feature\n" if($DEBUG5);
            }
        }

        my $prob = $numerator * $PR_TETHERING / $denominator;
        # my $prob = $numerator / $denominator;
        # print "  prob = $prob\n";
        print "  > probability = $prob\n" if($DEBUG7);

        if(exists $gt_info{HOST}{$this_ip} and $prob > $this_thresh) { 
            $tp ++; 
            print "  > TP\n" if($DEBUG7);
        }
        elsif(exists $gt_info{NORMAL}{$this_ip} and $prob <= $this_thresh) { 
            $tn ++; 
            print "  > TN\n" if($DEBUG7);
        }
        elsif(exists $gt_info{NORMAL}{$this_ip} and $prob > $this_thresh) { 
            $fp ++; 
            print "  > FP\n" if($DEBUG7);
        }
        elsif(exists $gt_info{HOST}{$this_ip} and $prob <= $this_thresh) { 
            $fn ++; 
            print "  > FN\n" if($DEBUG7);
        }
        else {die "wrong judgement\n";}
    }

    my $prec = MyUtil::precision($tp, $fn, $fp, $tn);
    my $recall = MyUtil::recall($tp, $fn, $fp, $tn);
    my $f1 = MyUtil::f1_score($prec, $recall);

    print "$this_thresh: f1=$f1 (prec=$prec, recall=$recall)\n" if($DEBUG7);
}
