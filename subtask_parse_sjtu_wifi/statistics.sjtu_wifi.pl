#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.15 @ UT Austin
##
## - input: 
##    
##
##  e.g.
##    perl statistics.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.2.bt0.s1
##    perl statistics.sjtu_wifi.pl sjtu_wifi.filter.dup1.host0.bt0.s1
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
my $input_dir  = "../processed_data/subtask_parse_sjtu_wifi/gen_trace";
# my $input_dir  = "../processed_data/subtask_sim_trace/gen_trace";
my $output_dir = "../processed_data/subtask_parse_sjtu_wifi/statistics";

my $filename;
my $gt_filename;
my $output_filename;

my %ip_info = ();
my %gt_info = ();
my %stat_info = ();
my %detected_ips = ();
my %feature_info = ();
my %os_feature_info = ();
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
    if($DEBUG4) {
        print "\n  - $this_ip";
        if(exists $gt_info{HOST}{$this_ip}) {
            print "(Tethering!! ".$gt_info{HOST}{$this_ip}{ORIG_IP}.")\n";
            print "    tether IP=".$gt_info{HOST}{$this_ip}{DUP_IP}." (".$gt_info{HOST}{$this_ip}{DUP_ORIG_IP}.")\n";
        }
        else {
            print "(".$gt_info{NORMAL}{$this_ip}{ORIG_IP}.")\n";
        }
        # print "\n";
    }

    my $cnt_heuristics = 0;
    my $cnt_detect = 0;
    my $has_feature;
    my $this_os = "";
    my $is_tether = 0;
    $is_tether = 1 if(exists $gt_info{HOST}{$this_ip});



    #############
    ## Identify OS by User Agent
    #############
    $heuristic = "user_agent";
    $cnt_heuristics ++;
    my @ua = keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{UA} };
    my @ua_os = Tethering::identify_os(\@ua);
    my $this_os = "";
    if(@ua_os == 1) {
        $this_os = $ua_os[0];
        $stat_info{OS}{$this_os}{CNT} ++;
        $stat_info{OS_SUM} ++;
    }
    # print "    $this_os\n";
    print "    ".join(", ", @ua_os)."\n";
    # die "more than one OS: ".join(",", @ua_os)."\n" if(@ua_os > 1);

    # if(scalar(@ua_os) == 0) {
    #     ## no OS detected
    #     my $feature = "no_user_agent";
    #     $feature_info{FEATURE}{$feature}{CNT} ++;
    #     $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});
    # }
    # elsif(scalar(@ua_os) == 1) {
    #     ## detect 1 OS
    #     my $feature = "user_agent_os==1";
    #     $feature_info{FEATURE}{$feature}{CNT} ++;
    #     $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});

    #     ## for OS features
    #     $this_os = $ua_os[0];
    #     if(exists $gt_info{NORMAL}{$this_ip}) {
    #         $os_feature_info{SRC}{$this_ip} = 1;
    #         $os_feature_info{OS}{$this_os}{CNT} ++;
    #     }
    # }
    # elsif(scalar(@ua_os) > 1) {
    #     ## detect 1 OS
    #     my $feature = "user_agent_os>1";
    #     $feature_info{FEATURE}{$feature}{CNT} ++;
    #     $feature_info{FEATURE}{$feature}{TETHER_CNT} ++ if(exists $gt_info{HOST}{$this_ip});
    # }
    
    
    #############
    ## Check TTL features: in tethering network
    ## 1. TTL in the network
    ## 2. TTL of different OS
    ## 3. # of distinct TTL per IP
    ## 4. table of probability
    ## 5. precision / recall using TTL
    #############
    my @ttls = (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{TTL} });
    if($this_os ne "") {
        foreach my $this_ttl (@ttls) {
            my $this_ttl_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{TTL}{$this_ttl};
            $stat_info{OS}{$this_os}{TTL}{$this_ttl} += $this_ttl_num;
            $stat_info{OS}{$this_os}{TTL_SUM} += $this_ttl_num;
            $stat_info{OS_TTL_SUM}{$this_os} += $this_ttl_num;
        }    
    }
    
    $stat_info{NETWORK}{TTL_NUM}{scalar(@ttls)} ++;
    $stat_info{NETWORK}{TTL_NUM_SUM} ++;
    
    
    #############
    ## Check TTL-gap features
    #############
    my @gap_thresholds = (1, 2, 4, 8, 16, 32);
    foreach my $gap_threshold (@gap_thresholds) {
        $heuristic = "gap_ttl_num.gap$gap_threshold";
        $cnt_heuristics ++;
        my $num_gat_ttl = TetheringFeatures::ttl_num_gap_num(\@ttls, $gap_threshold);
        
        $stat_info{NETWORK}{GAP_TTL}{$gap_threshold}{TTL_NUM}{$num_gat_ttl} ++;
        $stat_info{NETWORK}{GAP_TTL}{$gap_threshold}{TTL_NUM_SUM} ++;
    }



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
    
    if($this_os ne "") {
        print "    > ip_id_mono: $ratio_monotonic_pkts, $ratio_monotonic_flows\n";
        if($ratio_monotonic_pkts >= 0) {
            push(@{ $stat_info{OS}{$this_os}{IP_ID}{VIO_PKT_RATIO} }, 1-$ratio_monotonic_pkts);
        }
        if($ratio_monotonic_flows >= 0) {
            push(@{ $stat_info{OS}{$this_os}{IP_ID}{VIO_FLOW_RATIO} }, 1-$ratio_monotonic_flows);
        }
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
    foreach my $this_wsf (sort { $a <=> $b } (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE} }) ) {
        my $this_wsf_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE}{$this_wsf};

        # push(@{ $stat_info{NETWORK}{WSF}{$this_wsf} }, $this_wsf_num / $num_wsf);
        # push(@{ $stat_info{OS}{$this_os}{WSF}{$this_wsf} }, $this_wsf_num / $num_wsf) if($this_os ne "");
        $stat_info{NETWORK}{WSF}{$this_wsf} += $this_wsf_num;
        $stat_info{NETWORK}{WSF_SUM} += $this_wsf_num;

        if($this_os ne "") {
            $stat_info{OS}{$this_os}{WSF}{$this_wsf} += $this_wsf_num;
            $stat_info{OS}{$this_os}{WSF_SUM} += $this_wsf_num;
        }
    }

    my @sel_wsfs = (2, 4, 16, 64, 256);
    if($this_os ne "") {
        foreach my $this_wsf (@sel_wsfs) {
            my $this_wsf_num = 0;
            if(exists $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE}{$this_wsf}) {
                $this_wsf_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{WSSCALE}{$this_wsf};
            }
            push(@{ $stat_info{OS}{$this_os}{WSF_RATIO}{$this_wsf} }, $this_wsf_num / $num_wsf);

            print "    > wsf: $this_wsf=$this_wsf_num\n";
        }
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
    foreach my $this_kind (keys %{ $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND} }) {
        my $this_kind_num = $ip_info{SRC}{$this_ip}{ALL_FLOW}{OPT_KIND}{$this_kind};

        # print "$this_kind $this_kind_num $total_opt_all_num ".($this_kind_num/$total_opt_all_num)."\n";
        if($this_os ne "") {
            $stat_info{OS}{$this_os}{OPT_KIND}{$this_kind} += $this_kind_num;
            $stat_info{OS}{$this_os}{OPT_KIND_SUM} += $this_kind_num;
            # print "    $this_os: kind=$this_kind -> $this_kind_num\n";

            if($this_kind == 8) {
                $no_ts = 0;
                push(@{ $stat_info{OS}{$this_os}{TCP_TS} }, $this_kind_num / $total_opt_all_num);
                print "    > TS: ratio=".($this_kind_num / $total_opt_all_num)."\n";
            }
        }

        if($this_kind == 8) {
            $stat_info{IP}{TCP_TS} ++;
        }
    }
    if($no_ts and $this_os ne "") {
        push(@{ $stat_info{OS}{$this_os}{TCP_TS} }, 0);
        print "    > TS: ratio=0\n";
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
    


    #############
    ## Check clock frequency stability Heuristic
    #############
    my $flows_ref = \%{ $ip_info{SRC}{$this_ip} };
    my @freqs = (2, 10, 100, 200, 250, 1000);
    
    $heuristic = "freq_stability";
    $cnt_heuristics ++;
    my $rx_time_gap = 0.5;
    my ($this_freq, $freq_stdev) = TetheringFeatures::flow_frequency_stable_stdev($flows_ref, $rx_time_gap);
    print "    freq stdev: $freq_stdev\n";
    
    if($this_os ne "") {
        push(@{ $stat_info{OS}{$this_os}{FREQ_STAB}{STDEV} }, $freq_stdev) if($freq_stdev > 0);
        print "    > freq stab: ratio=$freq_stdev\n";
    }

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
    print "    bt stdev: $bt_stdev\n";

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
    
    

}



#############
## Output the statistics
#############
print "\nOutput the statistics\n" if($DEBUG2);

## OS
print "- OS\n";
$output_filename = "$filename.os.txt";
open FH, "> $output_dir/$output_filename" or die $!;
my $total_os_num = $stat_info{OS_SUM};
foreach my $this_os (sort (keys %{ $stat_info{OS} })) {
    my $this_os_num = $stat_info{OS}{$this_os}{CNT};
    print "$this_os $this_os_num $total_os_num ".($this_os_num/$total_os_num)."\n";
    print FH "$this_os $this_os_num $total_os_num ".($this_os_num/$total_os_num)."\n";
}
close FH;

## TTL ratio in the network
print "- TTL ratio in the network\n";
$output_filename = "$filename.ttl.network.txt";
open FH, "> $output_dir/$output_filename" or die $!;
my $total_ttl_num = $stat_info{NETWORK}{TTL_SUM};
foreach my $this_ttl (sort {$a <=> $b} (keys %{ $stat_info{NETWORK}{TTL} })) {
    my $this_ttl_num = $stat_info{NETWORK}{TTL}{$this_ttl};
    print "$this_ttl $this_ttl_num $total_ttl_num ".($this_ttl_num/$total_ttl_num)."\n";
    print FH "$this_ttl $this_ttl_num $total_ttl_num ".($this_ttl_num/$total_ttl_num)."\n";
}
close FH;

## TTL of different OS
print "- TTL of different OS\n";
foreach my $this_os (sort (keys %{ $stat_info{OS} })) {
    print "  $this_os\n";
    
    $output_filename = "$filename.ttl.os.$this_os.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my $total_ttl_num = $stat_info{OS}{$this_os}{TTL_SUM};
    foreach my $this_ttl (sort {$a <=> $b} (keys %{ $stat_info{OS}{$this_os}{TTL} })) {
        my $this_ttl_num = $stat_info{OS}{$this_os}{TTL}{$this_ttl};
        print "$this_ttl $this_ttl_num $total_ttl_num ".($this_ttl_num/$total_ttl_num)."\n";
        print FH "$this_ttl $this_ttl_num $total_ttl_num ".($this_ttl_num/$total_ttl_num)."\n";
    }

    close FH;
}


## number of distinct TTL per IP
print "- number of distinct TTL per IP\n";

$output_filename = "$filename.ttl.ip.txt";
open FH, "> $output_dir/$output_filename" or die $!;

my $total_ip_num = $stat_info{NETWORK}{TTL_NUM_SUM};
foreach my $this_ttl_num (sort {$a <=> $b } (keys %{ $stat_info{NETWORK}{TTL_NUM} })) {
    my $this_ttl_num_num = $stat_info{NETWORK}{TTL_NUM}{$this_ttl_num};
    print "$this_ttl_num $this_ttl_num_num $total_ip_num ".($this_ttl_num_num/$total_ip_num)."\n";
    print FH "$this_ttl_num $this_ttl_num_num $total_ip_num ".($this_ttl_num_num/$total_ip_num)."\n";
}

close FH;


## number of distinct gap TTL per IP
print "- number of distinct gap TTL per IP\n";
foreach my $this_gap (sort {$a <=> $b} (keys %{ $stat_info{NETWORK}{GAP_TTL} })) {
    print "  $this_gap\n";

    $output_filename = "$filename.ttl.gap.$this_gap.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my $total_ip_num = $stat_info{NETWORK}{GAP_TTL}{$this_gap}{TTL_NUM_SUM};
    foreach my $this_ttl_num (sort {$a <=> $b } (keys %{ $stat_info{NETWORK}{GAP_TTL}{$this_gap}{TTL_NUM} })) {
        my $this_ttl_num_num = $stat_info{NETWORK}{GAP_TTL}{$this_gap}{TTL_NUM}{$this_ttl_num};
        print "$this_ttl_num $this_ttl_num_num $total_ip_num ".($this_ttl_num_num/$total_ip_num)."\n";
        print FH "$this_ttl_num $this_ttl_num_num $total_ip_num ".($this_ttl_num_num/$total_ip_num)."\n";
    }    

    close FH;
}


## ratio of pkts which violate IP monotonicity
print "- ratio of pkts which violate IP monotonicity\n";
foreach my $this_os (sort (keys %{ $stat_info{OS} })) {
    print "  $this_os\n";

    if(exists $stat_info{OS}{$this_os}{IP_ID}{VIO_PKT_RATIO}) {
        $output_filename = "$filename.ip_id_mono.os.$this_os.pkt.txt";
        open FH, "> $output_dir/$output_filename" or die $!;

        my @vio_pkt_ratio = sort { $a <=> $b } (@{ $stat_info{OS}{$this_os}{IP_ID}{VIO_PKT_RATIO} });
        print "pkts=".join("\n", @vio_pkt_ratio)."\n";
        print FH join("\n", @vio_pkt_ratio);
        close FH;
    }
    
    if(exists $stat_info{OS}{$this_os}{IP_ID}{VIO_FLOW_RATIO}) {
        $output_filename = "$filename.ip_id_mono.os.$this_os.flow.txt";
        open FH, "> $output_dir/$output_filename" or die $!;

        my @vio_flow_ratio = sort { $a <=> $b } (@{ $stat_info{OS}{$this_os}{IP_ID}{VIO_FLOW_RATIO} });
        print "flows=".join("\n", @vio_flow_ratio)."\n";
        print FH join("\n", @vio_flow_ratio);
        close FH;
    }

}


## ratio of WSF==x of each OS
print "- ratio of WSF==x of each OS\n";
foreach my $this_os (sort (keys %{ $stat_info{OS} })) {
    print "  $this_os\n";

    $output_filename = "$filename.wsf.os.$this_os.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my $total_wsf_sum = $stat_info{OS}{$this_os}{WSF_SUM};
    foreach my $this_wsf (sort { $a <=> $b} (keys %{ $stat_info{OS}{$this_os}{WSF} })) {
        my $this_wsf_num = $stat_info{OS}{$this_os}{WSF}{$this_wsf};
        print "$this_wsf $this_wsf_num $total_wsf_sum ".($this_wsf_num / $total_wsf_sum)."\n";
        print FH "$this_wsf $this_wsf_num $total_wsf_sum ".($this_wsf_num / $total_wsf_sum)."\n";
    }

    close FH;
}

## ratio of WSF in each IP
# print "- ratio of WSF in each IP\n";
# my @sel_wsfs = (2, 4, 16, 64, 256);
# foreach my $this_os (sort (keys %{ $stat_info{OS} })) {
#     print "  $this_os\n";
    
#     foreach my $this_wsf (@sel_wsfs) {
        
#         my @wsf_ratios = sort { $a <=> $b } (@{ $stat_info{OS}{$this_os}{WSF_RATIO}{$this_wsf} });
#         print "$this_wsf ".join(" ", @wsf_ratios)."\n";
#     }
# }


## ratio of TCP Options in different OS
print "- ratio of TCP Options in different OS\n";

foreach my $this_os (keys %{ $stat_info{OS} }) {
    print "  $this_os\n";

    $output_filename = "$filename.opt.os.$this_os.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my $total_pkt_num = $stat_info{OS}{$this_os}{OPT_KIND_SUM};
    foreach my $this_kind (sort {$a <=> $b} (keys %{ $stat_info{OS}{$this_os}{OPT_KIND} })) {
        my $this_kind_num = $stat_info{OS}{$this_os}{OPT_KIND}{$this_kind};

        if($this_kind == -1) {
            print "\"no Opt\"";
            print FH "\"no Opt\"";
        }
        elsif($this_kind == 3) {
            print "\"WS Opt\"";
            print FH "\"WS Opt\"";
        }
        elsif($this_kind == 8) {
            print "\"TS Opt\"";
            print FH "\"TS Opt\"";
        }
        else {
            print "$this_kind";
            print FH "$this_kind";
        }

        print " $this_kind_num $total_pkt_num ".($this_kind_num/$total_pkt_num)."\n";
        print FH " $this_kind_num $total_pkt_num ".($this_kind_num/$total_pkt_num)."\n";

    }

    close FH;
}

## ratio of IPs/flows with TCP TS Option
print "- ratio of IPs/flows with TCP TS Option\n";
print "  flows ".$stat_info{FLOW}{TCP_TS}." ".$stat_info{FLOW}{TCP_TS_SUM}." ".($stat_info{FLOW}{TCP_TS} / $stat_info{FLOW}{TCP_TS_SUM})."\n";
print "  IPs ".$stat_info{IP}{TCP_TS}." ".$stat_info{IP}{TCP_TS_SUM}." ".($stat_info{IP}{TCP_TS} / $stat_info{IP}{TCP_TS_SUM})."\n";

## CCDF of ratio of packets with TCP TS
print "- CCDF of ratio of packets with TCP TS\n";

foreach my $this_os (keys %{ $stat_info{OS} }) {
    print "  $this_os\n";

    $output_filename = "$filename.ts.os.$this_os.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my @ratio_pkts_w_ts = (sort {$a <=> $b} (@{ $stat_info{OS}{$this_os}{TCP_TS} }));
    print "".join(" ", @ratio_pkts_w_ts)."\n";
    print FH "".join("\n", @ratio_pkts_w_ts)."\n";
    close FH;
}


## ratio of pkts violating TS monotonicity
print "- ratio of pkts violating TS monotonicity\n";

foreach my $this_is_tether (keys %{ $stat_info{NETWORK}{TS_MONO} }) {
    # print "  $this_is_tether\n";
    my $is_tether = "normal";
    if($this_is_tether eq "TETHER") {
        $is_tether = "tether";
    }

    foreach my $this_feature (sort (keys %{ $stat_info{NETWORK}{TS_MONO}{$this_is_tether} })) {
        # print "    $this_feature\n";

        my $this_feature_name;
        if($this_feature eq "DISORDER_RATIO") {
            $this_feature_name = "disorder.ratio";
        }
        elsif($this_feature eq "DISORDER_NUM") {
            $this_feature_name = "disorder.num";
        }
        elsif($this_feature eq "LARGE_GAP_RATIO") {
            $this_feature_name = "gap.ratio";
        }
        elsif($this_feature eq "LARGE_GAP_NUM") {
            $this_feature_name = "gap.num";
        }
        else {
            die "wrong feature for TS MONO\n";
        }

        $output_filename = "$filename.ts_mono.$this_feature_name.$is_tether.txt";
        open FH, "> $output_dir/$output_filename" or die $!;

        my @values = (0);
        if(exists $stat_info{NETWORK}{TS_MONO}{$this_is_tether}{$this_feature}) {
            @values = sort {$a <=> $b} (@{ $stat_info{NETWORK}{TS_MONO}{$this_is_tether}{$this_feature} });
        }
        print "$is_tether - $this_feature_name: ".join(",", @values)."\n";
        print FH join("\n", @values)."\n";
        close FH;
    }
}


## frequency stability
print "- frequency stability\n";
foreach my $this_os (keys %{ $stat_info{OS} }) {
    print "  $this_os\n";

    $output_filename = "$filename.freq_stab.os.$this_os.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my @stdevs = (0);
    if(exists $stat_info{OS}{$this_os}{FREQ_STAB}{STDEV} ) {
        @stdevs = sort {$a <=> $b} @{ $stat_info{OS}{$this_os}{FREQ_STAB}{STDEV} };
        print "".join(" ", @stdevs)."\n";
        print FH join("\n", @stdevs);
    }
    close FH;
}


## same frequency
print "- same frequency\n";

if(exists $stat_info{NETWORK}{FREQ}{TETHER}{STDEV}) {
    $output_filename = "$filename.freq.tether.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my @stdevs = sort {$a <=> $b} @{ $stat_info{NETWORK}{FREQ}{TETHER}{STDEV} };
    print "tether: ".join(" ", @stdevs)."\n";
    print FH join("\n", @stdevs);
    close FH;
}

if(exists $stat_info{NETWORK}{FREQ}{NORMAL}{STDEV}) {
    $output_filename = "$filename.freq.normal.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my @stdevs = sort {$a <=> $b} @{ $stat_info{NETWORK}{FREQ}{NORMAL}{STDEV} };
    print "normal: ".join(" ", @stdevs)."\n";
    print FH join("\n", @stdevs);
    close FH;
}


## same boot time
print "- same boot time\n";

if(exists $stat_info{NETWORK}{BOOT_TIME}{TETHER}{STDEV}) {
    $output_filename = "$filename.bt.tether.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my @stdevs = sort {$a <=> $b} @{ $stat_info{NETWORK}{BOOT_TIME}{TETHER}{STDEV} };
    print "tether: ".join(" ", @stdevs)."\n";
    print FH join("\n", @stdevs);
    close FH;
}

if(exists $stat_info{NETWORK}{BOOT_TIME}{NORMAL}{STDEV}) {
    $output_filename = "$filename.bt.normal.txt";
    open FH, "> $output_dir/$output_filename" or die $!;

    my @stdevs = sort {$a <=> $b} @{ $stat_info{NETWORK}{BOOT_TIME}{NORMAL}{STDEV} };
    print "normal: ".join(" ", @stdevs)."\n";
    print FH join("\n", @stdevs);
    close FH;
}





