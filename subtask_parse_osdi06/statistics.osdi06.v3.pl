#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.15 @ UT Austin
##
## - input: 
##    
##
##  e.g.
##    perl statistics.osdi06.v3.pl osdi06.filter.dup1.host0.2.bt0.s1
##    perl statistics.osdi06.v3.pl osdi06.filter.dup1.host0.bt0.s1 osdi06.filter.dup1.host0.bt0.s1
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
my $DEBUG5 = 0;     ## os file


#############
# Constants
#############
my $MIN_NUM_PKTS = 0;


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_parse_osdi06/gen_trace";
my $output_dir = "../processed_data/subtask_parse_osdi06/statistics";
my $output_prob_dir = "../processed_data/subtask_parse_osdi06/prob";

my $filename;
my $gt_filename;
my $output_filename;
my $prob_filename;

my %ip_info = ();
my %gt_info = ();
my %stat_info = ();
my %detected_ips = ();
my %feature_info = ();
my %os_feature_info = ();
my $heuristic;
my %out_info = ();
my %out_value_info = ();


#############
# check input
#############
print "check input\n" if($DEBUG2);
if(@ARGV < 1) {
    print "wrong number of input\n";
    exit;
}
$filename = $ARGV[0];
$prob_filename = $filename;
if(@ARGV == 2) {
    $prob_filename = $ARGV[1];
}
$gt_filename = "$filename.gt";
$output_filename = "$filename";

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


# my %prob_ind_os_info = read_os_prob("$output_prob_dir/$prob_filename.ind_os_prob.txt");
# foreach my $this_f (keys %prob_ind_os_info) {
#     print "$this_f\n";
#     foreach my $this_v (keys %{ $prob_ind_os_info{$this_f}{VALUE} }) {
#         print "  $this_v\n";
#         foreach my $this_os (keys %{ $prob_ind_os_info{$this_f}{VALUE}{$this_v}{OS} }) {
#             print "    $this_os -- ".$prob_ind_os_info{$this_f}{VALUE}{$this_v}{OS}{$this_os}{PR_OS_F}."\n";
#         }
#     }
# }
# exit;

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


    ## User Agent
    $ip_info{SRC}{$src}{ALL_FLOW}{UA}{$ua} = 1 if($ua ne "");

    ## TTL
    $ip_info{SRC}{$src}{ALL_FLOW}{TTL}{$ttl} ++;
    $stat_info{NETWORK}{TTL}{$ttl} ++;
    $stat_info{NETWORK}{TTL_SUM} ++;


    ## TCP TS
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
        $ip_info{SRC}{$src}{ALL_FLOW}{WSSCALE}{$wsscale} ++;
        $ip_info{SRC}{$src}{ALL_FLOW}{WSSCALE_CNT} ++;
    }
    else
    {
        $ip_info{SRC}{$src}{ALL_FLOW}{NO_WSSCALE_CNT} ++;
    }

    if($opt_kind ne "") {
        my @kinds = split(/,/, $opt_kind);
        foreach my $kind (@kinds) {
            $kind += 0;
            $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND}{$kind} ++;
            $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND_YES_SUM} ++;
            $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND_ALL_SUM} ++;
            $ip_info{SRC}{$src}{CONN}{"$dst.$sport.$dport"}{OPT_KIND}{$kind} ++;
        }
        $ip_info{SRC}{$src}{ALL_FLOW}{NUM_OPT_KIND}{scalar(@kinds)} ++;
    }
    else {
        $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND}{-1} ++;
        $ip_info{SRC}{$src}{ALL_FLOW}{OPT_KIND_ALL_SUM} ++;
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
    
    my $cnt_heuristics = 0;
    my $cnt_detect = 0;
    my $has_feature;
    my $this_os = "";
    my $is_tether = 0;
    $is_tether = 1 if(exists $gt_info{HOST}{$this_ip});
    $out_info{IP}{$this_ip}{TETHERING} = $is_tether;
    $stat_info{TETHERING}{$is_tether}{CNT} ++;


    #############
    ## Identify OS by User Agent
    #############
    $heuristic = "user_agent";
    $cnt_heuristics ++;
    my @ua = keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{UA} };
    my @ua_os = Tethering::identify_os(\@ua);
    if(@ua_os >= 1) {
        $this_os = join("|", @ua_os);
    }
    # if(@ua_os == 1) {
    # foreach my $tmp (@ua_os) {
    #     # $this_os = $ua_os[0];
    #     $stat_info{OS}{$tmp}{CNT} ++;
    #     $stat_info{OS_SUM} ++;
    # }
    $stat_info{OS}{$this_os}{CNT} ++;
    $stat_info{OS_SUM} ++;
    # print "    ".join(", ", @ua_os)."\n";
    $out_info{IP}{$this_ip}{OS} = $this_os;
    
    
    
    
    #############
    ## Check TTL features: in tethering network
    ## 1. TTL in the network
    ## 2. TTL of different OS
    ## 3. # of distinct TTL per IP
    ## 4. table of probability
    ## 5. precision / recall using TTL
    #############
    my @ttls = (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{TTL} });
    
    $out_info{IP}{$this_ip}{"TTL: w/ 128"} = 0;
    $out_info{IP}{$this_ip}{"TTL: w/o 128"} = 1;
    foreach my $this_ttl (@ttls) {
        my $this_ttl_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{TTL}{$this_ttl};
        $stat_info{OS}{$this_os}{TTL}{$this_ttl} += $this_ttl_num;
        $stat_info{OS}{$this_os}{TTL_SUM} += $this_ttl_num;
        $stat_info{OS_TTL_SUM}{$this_os} += $this_ttl_num;

        if($this_ttl > 125 and $this_ttl < 130) {
            # print "    > ttl: 128\n";
            $out_info{IP}{$this_ip}{"TTL: w/ 128"} = 1;
            $out_info{IP}{$this_ip}{"TTL: w/o 128"} = 0;
        }
    }

    $out_value_info{IP}{$this_ip}{"TTL"} = join("|", @ttls);

    $stat_info{NETWORK}{TTL_NUM}{scalar(@ttls)} ++;
    $stat_info{NETWORK}{TTL_NUM_SUM} ++;
    
    
    #############
    ## Check TTL-gap features
    #############
    my $gap_threshold = 4;
    
    $heuristic = "gap_ttl_num.gap$gap_threshold";
    $cnt_heuristics ++;
    my $num_gat_ttl = TetheringFeatures::ttl_num_gap_num(\@ttls, $gap_threshold);
    
    $stat_info{NETWORK}{GAP_TTL}{$gap_threshold}{TTL_NUM}{$num_gat_ttl} ++;
    $stat_info{NETWORK}{GAP_TTL}{$gap_threshold}{TTL_NUM_SUM} ++;

    if($num_gat_ttl <= 1) {
        $out_info{IP}{$this_ip}{"TTL number=1"} = 1;
        $out_info{IP}{$this_ip}{"TTL number>1"} = 0;
    }
    else {
        $out_info{IP}{$this_ip}{"TTL number=1"} = 0;
        $out_info{IP}{$this_ip}{"TTL number>1"} = 1;
    }
    $out_value_info{IP}{$this_ip}{"TTL number"} = $num_gat_ttl;
    



    #############
    ## Check IP ID monotonicity
    ## 1. ratio of violation for IPs in different OS
    ## 2. ratio of violation for flows in different OS
    ## 3. table of probability that
    ##       Pr(monotonic pkts | OS)
    ##       Pr(monotonic flows | OS)
    ##       Pr(not monotonic | OS)
    ##       Pr(monotonic pkts | tethering)
    ##       Pr(monotonic flows | tethering)  -- does not have strong connection
    ##       Pr(not monotonic | tethering)  -- does not have strong connection
    ## 4. precision and recall using "nonotonic pkts"
    ## 5. accuracy of identifying OS
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
    my ($ratio_monotonic_pkts, $ratio_monotonic_flows) = TetheringFeatures::ip_id_monotonicity_ratio(\@ip_ids, $ip_ids_flow_ref);
    
    # print "    > ip_id_mono: $ratio_monotonic_pkts, $ratio_monotonic_flows\n";
    if($ratio_monotonic_pkts >= 0) {
        my $ratio_violation = 1-$ratio_monotonic_pkts;
        push(@{ $stat_info{OS}{$this_os}{IP_ID}{VIO_PKT_RATIO} }, $ratio_violation);

        if($ratio_violation < 0.01) {
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts: N/A"} = 0;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts<1%"} = 1;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts=[1-40%)"} = 0;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts>=40%"} = 0;
        }
        elsif($ratio_violation >= 0.01 and $ratio_violation < 0.4) {
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts: N/A"} = 0;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts<1%"} = 0;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts=[1-40%)"} = 1;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts>=40%"} = 0;
        }
        elsif($ratio_violation >= 0.4) {
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts: N/A"} = 0;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts<1%"} = 0;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts=[1-40%)"} = 0;
            $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts>=40%"} = 1;
        }
        else {
            die "unknown type\n";
        }
        $out_value_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts"} = $ratio_violation;
    }
    else {
        $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts: N/A"} = 1;
        $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts<1%"} = 0;
        $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts=[1-40%)"} = 0;
        $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts>=40%"} = 0;
        $out_value_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts"} = 0;
    }

    if($ratio_monotonic_flows >= 0) {
        push(@{ $stat_info{OS}{$this_os}{IP_ID}{VIO_FLOW_RATIO} }, 1-$ratio_monotonic_flows);
    }
    
    



    #############
    ## Check Window Scale
    ## 1. WSF values of different OS
    ## 2. Table of probability
    ##      Pr(WSF | OS)
    ## 3. accuracy of identifying OS
    #############
    $heuristic = "win_scale";
    $cnt_heuristics ++;

    my $num_wsf = $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE_CNT};
    my $num_no_wsf = $ip_info{SRC}{$this_ip}{ALL_FLOW}{NO_WSSCALE_CNT};

    $out_info{IP}{$this_ip}{"WSF:N/A"} = 1;
    $out_info{IP}{$this_ip}{"WSF=4"} = 0;
    $out_info{IP}{$this_ip}{"WSF=16"} = 0;
    $out_info{IP}{$this_ip}{"WSF=64"} = 0;
    $out_info{IP}{$this_ip}{"WSF=256"} = 0;
    $out_info{IP}{$this_ip}{"WSF:others"} = 0;
    $out_value_info{IP}{$this_ip}{"WSF"} = "";

    foreach my $this_wsf (sort { $a <=> $b } (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE} }) ) {
        my $this_wsf_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE}{$this_wsf};

        # push(@{ $stat_info{NETWORK}{WSF}{$this_wsf} }, $this_wsf_num / $num_wsf);
        # push(@{ $stat_info{OS}{$this_os}{WSF}{$this_wsf} }, $this_wsf_num / $num_wsf) if($this_os ne "");
        $stat_info{NETWORK}{WSF}{$this_wsf} += $this_wsf_num;
        $stat_info{NETWORK}{WSF_SUM} += $this_wsf_num;

        $stat_info{OS}{$this_os}{WSF}{$this_wsf} += $this_wsf_num;
        $stat_info{OS}{$this_os}{WSF_SUM} += $this_wsf_num;

        $out_info{IP}{$this_ip}{"WSF:N/A"} = 0;
        if($this_wsf == 4 or $this_wsf == 16 or $this_wsf == 64 or $this_wsf == 256) {
            $out_info{IP}{$this_ip}{"WSF=$this_wsf"} = 1;
        }
        else {
            $out_info{IP}{$this_ip}{"WSF:others"} = 1;
        }
        
        $out_value_info{IP}{$this_ip}{"WSF"} .= "|$this_wsf($this_wsf_num)";
    }

    my @sel_wsfs = (4, 16, 64, 256);
    foreach my $this_wsf (@sel_wsfs) {
        my $this_wsf_num = 0;
        if(exists $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE}{$this_wsf}) {
            $this_wsf_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE}{$this_wsf};
        }
        if($num_wsf > 0) {
            push(@{ $stat_info{OS}{$this_os}{WSF_RATIO}{$this_wsf} }, $this_wsf_num / $num_wsf);
        }
        else {
            push(@{ $stat_info{OS}{$this_os}{WSF_RATIO}{$this_wsf} }, 0);
        }
        # print "    > wsf: $this_wsf=$this_wsf_num\n";
    }


    #############
    ## Check TCP Timestamp Option (kind = 8)
    ## 1. # TCP Options in different OS
    ## 2. # flows have TCP TS
    #############
    $stat_info{IP}{TCP_TS_SUM} ++;

    # my $total_opt_yes_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND_YES_SUM};
    my $total_opt_all_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND_ALL_SUM};
    my $no_ts = 1;

    $out_info{IP}{$this_ip}{"TS ratio<1%"} = 1;
    $out_info{IP}{$this_ip}{"TS ratio>=1%"} = 0;
    $out_value_info{IP}{$this_ip}{"TS ratio"} = 0;

    foreach my $this_kind (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND} }) {
        my $this_kind_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND}{$this_kind};

        # print "$this_kind $this_kind_num $total_opt_all_num ".($this_kind_num/$total_opt_all_num)."\n";
        $stat_info{OS}{$this_os}{OPT_KIND}{$this_kind} += $this_kind_num;
        $stat_info{OS}{$this_os}{OPT_KIND_SUM} += $this_kind_num;
        # print "    $this_os: kind=$this_kind -> $this_kind_num\n";

        if($this_kind == 8) {
            $no_ts = 0;
            push(@{ $stat_info{OS}{$this_os}{TCP_TS} }, $this_kind_num / $total_opt_all_num);
            # print "    > TS: ratio=".($this_kind_num / $total_opt_all_num)."\n";

            if($this_kind_num / $total_opt_all_num >= 0.01) {
                $out_info{IP}{$this_ip}{"TS ratio<1%"} = 0;
                $out_info{IP}{$this_ip}{"TS ratio>=1%"} = 1;
            }
            $out_value_info{IP}{$this_ip}{"TS ratio"} = $this_kind_num / $total_opt_all_num;
        }

        if($this_kind == 8) {
            $stat_info{IP}{TCP_TS} ++;
        }
    }
    if($no_ts) {
        push(@{ $stat_info{OS}{$this_os}{TCP_TS} }, 0);
    }

    foreach my $this_f (keys %{ $ip_info{SRC}{$this_ip}{CONN} }) {
        $stat_info{FLOW}{TCP_TS_SUM} ++;

        foreach my $this_kind (keys %{ $ip_info{SRC}{$this_ip}{CONN}{$this_f}{OPT_KIND} }) {
            next if($this_kind != 8);

            $stat_info{FLOW}{TCP_TS} ++;
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
    
    my $freq_thresh = 1000;

    $heuristic = "ts_monotonicity.freq$freq_thresh";
    $cnt_heuristics ++;
    my ($ratio_disorder, $ratio_large_gap) = TetheringFeatures::timestamp_monotonicity_ratio(\@rx_times, \@tx_times, $freq_thresh);
    my $num_disorder = scalar(@rx_times) * $ratio_disorder;
    my $num_large_gap = scalar(@tx_times) * $ratio_large_gap;

    if($ratio_disorder >= 0) {
        if($is_tether) {
            push(@{ $stat_info{NETWORK}{TS_MONO}{TETHER}{DISORDER_RATIO} }, $ratio_disorder);
            push(@{ $stat_info{NETWORK}{TS_MONO}{TETHER}{DISORDER_NUM} }, $num_disorder);    
        }
        else {
            push(@{ $stat_info{NETWORK}{TS_MONO}{NORMAL}{DISORDER_RATIO} }, $ratio_disorder);
            push(@{ $stat_info{NETWORK}{TS_MONO}{NORMAL}{DISORDER_NUM} }, $num_disorder);    
        }
        
    }

    if($ratio_disorder < 0.01) {
        $out_info{IP}{$this_ip}{"TS mono - ratio of violating pkts<1%"} = 1;
        $out_info{IP}{$this_ip}{"TS mono - ratio of violating pkts>=1%"} = 0;
    }
    else {
        $out_info{IP}{$this_ip}{"TS mono - ratio of violating pkts<1%"} = 0;
        $out_info{IP}{$this_ip}{"TS mono - ratio of violating pkts>=1%"} = 1;
    }
    $out_value_info{IP}{$this_ip}{"TS mono - ratio of violating pkts"} = $ratio_disorder;

    if($ratio_large_gap >= 0) {
        if($is_tether) {
            push(@{ $stat_info{NETWORK}{TS_MONO}{TETHER}{LARGE_GAP_RATIO} }, $ratio_large_gap);
            push(@{ $stat_info{NETWORK}{TS_MONO}{TETHER}{LARGE_GAP_NUM} }, $num_large_gap);
        }
        else {
            push(@{ $stat_info{NETWORK}{TS_MONO}{NORMAL}{LARGE_GAP_RATIO} }, $ratio_large_gap);
            push(@{ $stat_info{NETWORK}{TS_MONO}{NORMAL}{LARGE_GAP_NUM} }, $num_large_gap);
        }
    }

    if($num_large_gap < 2) {
        $out_info{IP}{$this_ip}{"TS mono - number of large TS itvl<2"} = 1;
        $out_info{IP}{$this_ip}{"TS mono - number of large TS itvl>=2"} = 0;
    }
    else {
        $out_info{IP}{$this_ip}{"TS mono - number of large TS itvl<2"} = 0;
        $out_info{IP}{$this_ip}{"TS mono - number of large TS itvl>=2"} = 1;
    }
    $out_value_info{IP}{$this_ip}{"TS mono - number of large TS itvl"} = $num_large_gap;
    


    #############
    ## Check clock frequency stability Heuristic
    #############
    my $flows_ref = \%{ $ip_info{SRC}{$this_ip} };
    my @freqs = (1, 10, 100, 128, 1000);
    
    $heuristic = "freq_stability";
    $cnt_heuristics ++;
    my $rx_time_gap = 1;
    my ($this_freq, $freq_stdev) = TetheringFeatures::flow_frequency_stable_stdev($flows_ref, $rx_time_gap);
    # print "    freq stdev: $freq_stdev\n";
    
    push(@{ $stat_info{OS}{$this_os}{FREQ_STAB}{STDEV} }, $freq_stdev) if($freq_stdev > 0);
    # print "    > freq stab: freq=$this_freq, stdev=$freq_stdev\n";

    #############################
    $out_info{IP}{$this_ip}{"freq:N/A"} = 1;
    foreach my $freq_cand (@freqs) {
        $out_info{IP}{$this_ip}{"freq=$freq_cand"} = 0;
    }
    $out_info{IP}{$this_ip}{"freq:others"} = 0;

    if($this_freq > 0) {
        $out_info{IP}{$this_ip}{"freq:N/A"} = 0;
        $out_info{IP}{$this_ip}{"freq:others"} = 1;

        foreach my $freq_cand (@freqs) {
            if(abs($this_freq - $freq_cand) < 5) {
                $out_info{IP}{$this_ip}{"freq=$freq_cand"} = 1;
                $out_info{IP}{$this_ip}{"freq:others"} = 0;
                last;
            }
        }
    }

    $out_value_info{IP}{$this_ip}{"freq"} = $this_freq;
    ##############################


    ##############################
    if($freq_stdev > 0 and $freq_stdev < 10) {
        $out_info{IP}{$this_ip}{"freq stdev < 10"} = 1;
        $out_info{IP}{$this_ip}{"freq stdev >= 10"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev:N/A"} = 0;
    }
    elsif($freq_stdev >= 10) {
        $out_info{IP}{$this_ip}{"freq stdev < 10"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev >= 10"} = 1;
        $out_info{IP}{$this_ip}{"freq stdev:N/A"} = 0;
    }
    else {
        $out_info{IP}{$this_ip}{"freq stdev < 10"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev >= 10"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev:N/A"} = 1;
    }
    $out_value_info{IP}{$this_ip}{"freq stdev"} = $freq_stdev;

    if($freq_stdev > 0 and $freq_stdev < 100) {
        $out_info{IP}{$this_ip}{"freq stdev < 100"} = 1;
        $out_info{IP}{$this_ip}{"freq stdev >= 100"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev:N/A"} = 0;
    }
    elsif($freq_stdev >= 100) {
        $out_info{IP}{$this_ip}{"freq stdev < 100"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev >= 100"} = 1;
        $out_info{IP}{$this_ip}{"freq stdev:N/A"} = 0;
    }
    else {
        $out_info{IP}{$this_ip}{"freq stdev < 100"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev >= 100"} = 0;
        $out_info{IP}{$this_ip}{"freq stdev:N/A"} = 1;
    }
    $out_value_info{IP}{$this_ip}{"freq stdev"} = $freq_stdev;
    ##############################

    if($is_tether) {
        push(@{ $stat_info{NETWORK}{FREQ}{TETHER}{STDEV} }, $freq_stdev) if($freq_stdev > 0);
    }
    else {
        push(@{ $stat_info{NETWORK}{FREQ}{NORMAL}{STDEV} }, $freq_stdev) if($freq_stdev > 0);
    }
    
    

    ############
    # Check boot time Heuristic
    ############
    my $bt_stdev = TetheringFeatures::boot_time_median_enumeration_stdev($flows_ref, \@freqs, $rx_time_gap);
    # print "    bt stdev: $bt_stdev\n";

    if($freq_stdev < 50) {
        if($this_os ne "") {
            push(@{ $stat_info{OS}{$this_os}{BOOT_TIME}{STDEV} }, $bt_stdev) if($bt_stdev > 0);
        }

        if($is_tether) {
            push(@{ $stat_info{NETWORK}{BOOT_TIME}{TETHER}{STDEV} }, $bt_stdev) if($bt_stdev > 0);
        }
        else {
            push(@{ $stat_info{NETWORK}{BOOT_TIME}{NORMAL}{STDEV} }, $bt_stdev) if($bt_stdev > 0);
        }    
    }
    
    ##############################
    if($bt_stdev > 0 and $bt_stdev < 500) {
        $out_info{IP}{$this_ip}{"boot time stdev < 500"} = 1;
        $out_info{IP}{$this_ip}{"boot time stdev >= 500"} = 0;
        $out_info{IP}{$this_ip}{"boot time stdev:N/A"} = 0;
    }
    elsif($bt_stdev >= 500) {
        $out_info{IP}{$this_ip}{"boot time stdev < 500"} = 0;
        $out_info{IP}{$this_ip}{"boot time stdev >= 500"} = 1;
        $out_info{IP}{$this_ip}{"boot time stdev:N/A"} = 0;
    }
    else {
        $out_info{IP}{$this_ip}{"boot time stdev < 500"} = 0;
        $out_info{IP}{$this_ip}{"boot time stdev >= 500"} = 0;
        $out_info{IP}{$this_ip}{"boot time stdev:N/A"} = 1;
    }
    $out_value_info{IP}{$this_ip}{"boot time stdev"} = $bt_stdev;
    ##############################


}




###############################
# my @oss = ("Android", "Apple", "Windows");
my @os_features = ("TTL: w/ 128", "TTL: w/o 128", "IP ID mono - ratio of violating pkts: N/A", "IP ID mono - ratio of violating pkts<1%", "IP ID mono - ratio of violating pkts=[1-40%)", "IP ID mono - ratio of violating pkts>=40%", "WSF:N/A", "WSF=4", "WSF=16", "WSF=64", "WSF=256", "WSF:others", "TS ratio<1%", "TS ratio>=1%", "freq:N/A", "freq=1", "freq=10", "freq=100", "freq=128", "freq=1000", "freq:others", "freq stdev < 10", "freq stdev >= 10", "freq stdev:N/A");
my @tethering_features = ("TTL number=1", "TTL number>1", "TS mono - ratio of violating pkts<1%", "TS mono - ratio of violating pkts>=1%", "TS mono - number of large TS itvl<2", "TS mono - number of large TS itvl>=2", "freq stdev < 100", "freq stdev >= 100", "freq stdev:N/A", "boot time stdev < 500", "boot time stdev >= 500", "boot time stdev:N/A");

my %prob_info = ();

print "\n, Pr(OS), ".join(", ", @os_features).", Total\n";
foreach my $this_os (sort keys %{ $stat_info{OS} }) {
    my $pr_os = $stat_info{OS}{$this_os}{CNT} / $stat_info{OS_SUM};

    my $total_feature = 0;
    foreach my $this_ip (sort (keys %{ $out_info{IP} })) {
        next if($this_os ne $out_info{IP}{$this_ip}{OS});
        
        print "$this_ip=".$out_info{IP}{$this_ip}{OS}.", $pr_os, ";

        ## Total feautre
        foreach my $this_f (@os_features) {
            print $out_info{IP}{$this_ip}{$this_f}.", ";
            $total_feature = 2*$total_feature + $out_info{IP}{$this_ip}{$this_f};
        }
        print "$total_feature\n";
        $out_info{IP}{$this_ip}{"OS features"} = $total_feature;
        # $prob_info{"OS features"}{VALUE}{$total_feature}{OS}{$this_os}{CNT} ++;
        # $prob_info{"OS features"}{VALUE}{$total_feature}{CNT} ++;

        ## TTL 128
        my $sum_feature = "TTL 128";
        $total_feature = 2*$out_info{IP}{$this_ip}{"TTL: w/ 128"} + $out_info{IP}{$this_ip}{"TTL: w/o 128"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{$this_os}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## IP ID mono - ratio of violating pkts
        $sum_feature = "IP ID mono - ratio of violating pkts";
        $total_feature = 8*$out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts: N/A"} + 4*$out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts<1%"} + 2*$out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts=[1-40%)"} + $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts>=40%"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{$this_os}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## WSF
        $sum_feature = "WSF";
        $total_feature = 32*$out_info{IP}{$this_ip}{"WSF:N/A"} + 16*$out_info{IP}{$this_ip}{"WSF=4"} + 8*$out_info{IP}{$this_ip}{"WSF=16"} + 4*$out_info{IP}{$this_ip}{"WSF=64"} + 2*$out_info{IP}{$this_ip}{"WSF=256"} + $out_info{IP}{$this_ip}{"WSF:others"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{$this_os}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## TS ratio
        $sum_feature = "TS ratio";
        $total_feature = 2*$out_info{IP}{$this_ip}{"TS ratio<1%"} + $out_info{IP}{$this_ip}{"TS ratio>=1%"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{$this_os}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## freq
        $sum_feature = "freq";
        $total_feature = 64*$out_info{IP}{$this_ip}{"freq:N/A"} + 32*$out_info{IP}{$this_ip}{"freq=1"} + 16*$out_info{IP}{$this_ip}{"freq=10"} + 8*$out_info{IP}{$this_ip}{"freq=100"} + 4*$out_info{IP}{$this_ip}{"freq=128"} + 2*$out_info{IP}{$this_ip}{"freq=1000"} + $out_info{IP}{$this_ip}{"freq:others"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{$this_os}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## freq stdev
        $sum_feature = "freq stdev";
        $total_feature = 4*$out_info{IP}{$this_ip}{"freq stdev < 10"} + 2*$out_info{IP}{$this_ip}{"freq stdev >= 10"} + $out_info{IP}{$this_ip}{"freq stdev:N/A"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{$this_os}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

    }
}

###################################
## Probability of tethering
print "\n, ".join(", ", @tethering_features).", Total\n";
foreach my $this_tethering (0,1) {
    my $total_feature = 0;
    foreach my $this_ip (sort (keys %{ $out_info{IP} })) {
        next if($this_tethering != $out_info{IP}{$this_ip}{TETHERING});
        
        print "$this_ip=".$out_info{IP}{$this_ip}{OS}."|".$out_info{IP}{$this_ip}{TETHERING}.", ";

        ## Total feautre
        foreach my $this_f (@tethering_features) {
            print $out_info{IP}{$this_ip}{$this_f}.", ";
            $total_feature = 2*$total_feature + $out_info{IP}{$this_ip}{$this_f};
        }
        print "$total_feature\n";
        $out_info{IP}{$this_ip}{"Tethering features"} = $total_feature;
        # $prob_info{"Tethering features"}{VALUE}{$total_feature}{TETHERING}{$this_tethering}{CNT} ++;
        # $prob_info{"Tethering features"}{VALUE}{$total_feature}{CNT} ++;

        ## TTL number
        my $sum_feature = "TTL number";
        $total_feature = 2*$out_info{IP}{$this_ip}{"TTL number=1"} + $out_info{IP}{$this_ip}{"TTL number>1"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{TETHERING}{$this_tethering}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## TS mono - ratio of violating pkts
        $sum_feature = "TS mono - ratio of violating pkts";
        $total_feature = 2*$out_info{IP}{$this_ip}{"TS mono - ratio of violating pkts<1%"} + $out_info{IP}{$this_ip}{"TS mono - ratio of violating pkts>=1%"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{TETHERING}{$this_tethering}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## TS mono - number of large TS itvl
        $sum_feature = "TS mono - number of large TS itvl";
        $total_feature = 2*$out_info{IP}{$this_ip}{"TS mono - number of large TS itvl<2"} + $out_info{IP}{$this_ip}{"TS mono - number of large TS itvl>=2"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{TETHERING}{$this_tethering}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## freq stdev
        $sum_feature = "freq stdev";
        $total_feature = 4*$out_info{IP}{$this_ip}{"freq stdev < 100"} + 2*$out_info{IP}{$this_ip}{"freq stdev >= 100"} + $out_info{IP}{$this_ip}{"freq stdev:N/A"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{TETHERING}{$this_tethering}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;

        ## boot time stdev
        $sum_feature = "boot time stdev";
        $total_feature = 4*$out_info{IP}{$this_ip}{"boot time stdev < 500"} + 2*$out_info{IP}{$this_ip}{"boot time stdev >= 500"} + $out_info{IP}{$this_ip}{"boot time stdev:N/A"};
        $out_info{IP}{$this_ip}{$sum_feature} = $total_feature;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{TETHERING}{$this_tethering}{CNT} ++;
        # $prob_info{$sum_feature}{VALUE}{$total_feature}{CNT} ++;
    }
}


# my @feature_values = ("TTL", "IP ID mono - ratio of violating pkts", "WSF", "TS ratio", "freq", "freq stdev", "TTL number", "TS mono - ratio of violating pkts", "TS mono - number of large TS itvl");

# print "\n, ".join(", ", @feature_values)."\n";
# foreach my $this_os (sort keys %{ $stat_info{OS} }) {
#     foreach my $this_ip (sort (keys %{ $out_info{IP} })) {
#         next if($this_os ne $out_info{IP}{$this_ip}{OS});
        
#         print "$this_ip=".$out_info{IP}{$this_ip}{OS}."|".$out_info{IP}{$this_ip}{TETHERING}.", ";

#         foreach my $this_f (@feature_values) {
#             print $out_value_info{IP}{$this_ip}{$this_f}.", ";
#         }
#         print "\n";
#     }
# }


###############################


%prob_info = read_os_prob("$output_prob_dir/$prob_filename.os_prob.txt");

# $output_filename = "results.$prob_filename--$filename.txt";
# open FH, "> $output_dir/$output_filename" or die $!;
# print FH ", Pr(OS), ".join(", ", @os_features).", Total, Pr(Android|Total), Pr(Apple|Total), Pr(Windows|Total), TTL 128, Pr(Android|TTL 128), Pr(Apple|TTL 128), Pr(Windows|TTL 128), IP ID mono, Pr(Android|IP ID mono), Pr(Apple|IP ID mono), Pr(Windows|IP ID mono), WSF, Pr(Android|WSF), Pr(Apple|WSF), Pr(Windows|WSF), TS ratio, Pr(Android|TS ratio), Pr(Apple|TS ratio), Pr(Windows|TS ratio), freq, Pr(Android|freq), Pr(Apple|freq), Pr(Windows|freq), freq stability, Pr(Android|freq stability), Pr(Apple|freq stability), Pr(Windows|freq stability), Pr(Android), Pr(Apple), Pr(Windows)\n";
# foreach my $this_os (sort keys %{ $stat_info{OS} }) {
#     my $pr_os = $stat_info{OS}{$this_os}{CNT} / $stat_info{OS_SUM};

#     my $total_feature = 0;
#     foreach my $this_ip (sort (keys %{ $out_info{IP} })) {
#         next if($this_os ne $out_info{IP}{$this_ip}{OS});
        
#         print FH "$this_ip=".$out_info{IP}{$this_ip}{OS}.", $pr_os, ";

#         foreach my $this_f (@os_features) {
#             print FH $out_info{IP}{$this_ip}{$this_f}.", ";
#             $total_feature = 2*$total_feature + $out_info{IP}{$this_ip}{$this_f};
#         }
#         print FH "$total_feature, ";
        
#         print FH $prob_info{"OS features"}{VALUE}{$total_feature}{OS}{"Android"}{PR_OS_F}.", ";
#         print FH $prob_info{"OS features"}{VALUE}{$total_feature}{OS}{"Apple"}{PR_OS_F}.", ";
#         print FH $prob_info{"OS features"}{VALUE}{$total_feature}{OS}{"Windows"}{PR_OS_F}.", ";

        
#         my $prod_and = 1;
#         my $prod_app = 1;
#         my $prod_win = 1;

#         ## TTL 128
#         my $sum_feature = "TTL 128";
#         $total_feature = 2*$out_info{IP}{$this_ip}{"TTL: w/ 128"} + $out_info{IP}{$this_ip}{"TTL: w/o 128"};
#         print FH "$total_feature, ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F}.", ";
#         $prod_and *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F};
#         $prod_app *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F};
#         $prod_win *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F};

#         ## IP ID mono - ratio of violating pkts
#         $sum_feature = "IP ID mono - ratio of violating pkts";
#         $total_feature = 8*$out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts: N/A"} + 4*$out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts<1%"} + 2*$out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts=[1-40%)"} + $out_info{IP}{$this_ip}{"IP ID mono - ratio of violating pkts>=40%"};
#         print FH "$total_feature, ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F}.", ";
#         $prod_and *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F};
#         $prod_app *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F};
#         $prod_win *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F};

#         ## WSF
#         $sum_feature = "WSF";
#         $total_feature = 32*$out_info{IP}{$this_ip}{"WSF:N/A"} + 16*$out_info{IP}{$this_ip}{"WSF=4"} + 8*$out_info{IP}{$this_ip}{"WSF=16"} + 4*$out_info{IP}{$this_ip}{"WSF=64"} + 2*$out_info{IP}{$this_ip}{"WSF=256"} + $out_info{IP}{$this_ip}{"WSF:others"};
#         print FH "$total_feature, ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F}.", ";
#         $prod_and *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F};
#         $prod_app *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F};
#         $prod_win *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F};

#         ## TS ratio
#         $sum_feature = "TS ratio";
#         $total_feature = 2*$out_info{IP}{$this_ip}{"TS ratio<1%"} + $out_info{IP}{$this_ip}{"TS ratio>=1%"};
#         print FH "$total_feature, ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F}.", ";
#         $prod_and *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F};
#         $prod_app *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F};
#         $prod_win *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F};

#         ## freq
#         $sum_feature = "freq";
#         $total_feature = 64*$out_info{IP}{$this_ip}{"freq:N/A"} + 32*$out_info{IP}{$this_ip}{"freq=1"} + 16*$out_info{IP}{$this_ip}{"freq=10"} + 8*$out_info{IP}{$this_ip}{"freq=100"} + 4*$out_info{IP}{$this_ip}{"freq=128"} + 2*$out_info{IP}{$this_ip}{"freq=1000"} + $out_info{IP}{$this_ip}{"freq:others"};
#         print FH "$total_feature, ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F}.", ";
#         $prod_and *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F};
#         $prod_app *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F};
#         $prod_win *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F};

#         ## freq stdev
#         $sum_feature = "freq stdev";
#         $total_feature = 4*$out_info{IP}{$this_ip}{"freq stdev < 10"} + 2*$out_info{IP}{$this_ip}{"freq stdev >= 10"} + $out_info{IP}{$this_ip}{"freq stdev:N/A"};
#         print FH "$total_feature, ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F}.", ";
#         print FH $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F}.", ";
#         $prod_and *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Android}{PR_OS_F};
#         $prod_app *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Apple}{PR_OS_F};
#         $prod_win *= $prob_info{$sum_feature}{VALUE}{$total_feature}{OS}{Windows}{PR_OS_F};

#         print FH "$prod_and, $prod_app, $prod_win\n";
#     }
# }
# close FH;


my %prob_ind_os_info = read_os_prob("$output_prob_dir/$prob_filename.ind_os_prob.txt");

$output_filename = "results.os.$prob_filename--$filename.txt";
open FH, "> $output_dir/$output_filename" or die $!;
print FH ", Pr(OS), ".join(", Pr(android|fi), Pr(iOS|fi), Pr(Win|fi), ", @os_features).", Pr(android|fi), Pr(iOS|fi), Pr(Win|fi), Pr(Android), Pr(Apple), Pr(Windows)\n";
foreach my $this_os (sort keys %{ $stat_info{OS} }) {
    my $pr_os = $stat_info{OS}{$this_os}{CNT} / $stat_info{OS_SUM};

    foreach my $this_ip (sort (keys %{ $out_info{IP} })) {
        next if($this_os ne $out_info{IP}{$this_ip}{OS});
        
        print "$this_ip=".$out_info{IP}{$this_ip}{OS}."|".$out_info{IP}{$this_ip}{TETHERING}.", $pr_os, ";
        print FH "$this_ip=".$out_info{IP}{$this_ip}{OS}.", $pr_os, ";

        my $prod_and = 1;
        my $prod_app = 1;
        my $prod_win = 1;

        foreach my $this_f (@os_features) {
            my $this_f_value = $out_info{IP}{$this_ip}{$this_f};
            
            my $prob_and_f = $prob_ind_os_info{$this_f}{VALUE}{$this_f_value}{OS}{"Android"}{PR_OS_F};
            my $prob_app_f = $prob_ind_os_info{$this_f}{VALUE}{$this_f_value}{OS}{"Apple"}{PR_OS_F};
            my $prob_win_f = $prob_ind_os_info{$this_f}{VALUE}{$this_f_value}{OS}{"Windows"}{PR_OS_F};
            
            if($this_f_value == 1) {
                print FH "$this_f_value, $prob_and_f, $prob_app_f, $prob_win_f, ";
                $prod_and *= $prob_and_f;
                $prod_app *= $prob_app_f;
                $prod_win *= $prob_win_f;
                print "$this_f_value, $prob_and_f ($prod_and), $prob_app_f ($prod_app), $prob_win_f ($prod_win), ";
                
            }
            elsif($this_f_value == 0) {
                print FH "$this_f_value, X, X, X, ";
            }
            else {
                die "unknown value: $this_f_value\n";
            }
        }
        print FH "$prod_and, $prod_app, $prod_win\n";
        print "$prod_and, $prod_app, $prod_win\n";
        $out_info{IP}{$this_ip}{PR_ANDROID} = $prod_and;
        $out_info{IP}{$this_ip}{PR_APPLE} = $prod_app;
        $out_info{IP}{$this_ip}{PR_WINDOWS} = $prod_win;
        # exit;
    }
}
close FH;


my %prob_ind_tethering_info = read_tethering_prob("$output_prob_dir/$prob_filename.ind_tethering_prob.txt");

$output_filename = "results.tether.$prob_filename--$filename.txt";
open FH, "> $output_dir/$output_filename" or die $!;

print FH ", Pr(Tethering), ".join(", Pr(Tethering|fi), ", @tethering_features).", Pr(Tethering|fi), Pr(Android), Pr(Apple), Pr(Windows), Pr(Tethering)\n";
my $pr_tethering = $stat_info{TETHERING}{1}{CNT} / ($stat_info{TETHERING}{1}{CNT} + $stat_info{TETHERING}{0}{CNT});

foreach my $this_tethering (0, 1){
    foreach my $this_ip (sort (keys %{ $out_info{IP} })) {
        next if($out_info{IP}{$this_ip}{TETHERING} != $this_tethering);
        
        print FH "$this_ip=$this_tethering, $pr_tethering, ";

        my $prod_tethering = 1;
        
        foreach my $this_f (@tethering_features) {
            my $this_f_value = $out_info{IP}{$this_ip}{$this_f};
            
            my $prob_tether_f = $prob_ind_tethering_info{$this_f}{VALUE}{$this_f_value}{TETHERING}{1}{PR_TETHER_F};
            
            if($this_f_value == 1) {
                print FH "$this_f_value, $prob_tether_f, ";
                $prod_tethering *= $prob_tether_f;
            }
            elsif($this_f_value == 0) {
                print FH "$this_f_value, X, ";
            }
            else {
                die "unknown value: $this_f_value\n";
            }
        }

        print FH "".$out_info{IP}{$this_ip}{PR_ANDROID}.", ".$out_info{IP}{$this_ip}{PR_APPLE}.", ".$out_info{IP}{$this_ip}{PR_WINDOWS}.", $prod_tethering, ";
        $prod_tethering *= (1-max($out_info{IP}{$this_ip}{PR_ANDROID}, $out_info{IP}{$this_ip}{PR_APPLE}, $out_info{IP}{$this_ip}{PR_WINDOWS}));
        print FH "$prod_tethering\n";
    }
}
close FH;

#############################################
## output probability
# $output_filename = "$filename.prob.txt";
# open FH, "> $output_prob_dir/$output_filename" or die $!;
# foreach my $this_f (sort keys %prob_info) {
#     foreach my $this_v (sort {$a <=> $b} keys %{ $prob_info{$this_f}{VALUE} }) {
#         foreach my $this_os ("Android", "Apple", "Windows") {
#             my $pr_os_f = $prob_info{$this_f}{VALUE}{$this_v}{OS}{$this_os}{PR_OS_F};
#             print "$this_f, $this_v, $this_os, $pr_os_f\n";
#             print FH "$this_f, $this_v, $this_os, $pr_os_f\n";
#         }
#     }
# }
# close FH;



1;


sub read_os_prob {
    my ($prob_filename) = @_;

    my %prob_info = ();
    open FH, "$prob_filename" or die "$prob_filename\n".$!;
    while(<FH>) {
        chomp;
        my ($f_name, $f_val, $os, $pr_os_f) = split(", ", $_);
        $f_val += 0; $pr_os_f += 0;

        $prob_info{$f_name}{VALUE}{$f_val}{OS}{$os}{PR_OS_F} = $pr_os_f;
    }
    close FH;

    return %prob_info;
}

sub read_tethering_prob {
    my ($prob_filename) = @_;

    my %prob_info = ();
    open FH, "$prob_filename" or die $!;
    while(<FH>) {
        chomp;
        my ($f_name, $f_val, $is_tether, $pr_tether_f) = split(", ", $_);
        $f_val += 0; $is_tether += 0; $pr_tether_f += 0;

        $prob_info{$f_name}{VALUE}{$f_val}{TETHERING}{$is_tether}{PR_TETHER_F} = $pr_tether_f;
    }
    close FH;

    return %prob_info;
}