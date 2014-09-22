#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.15 @ UT Austin
##
## - input: 
##    
##
##  e.g.
##    perl detect_tethering_multifiles.sjtu_wifi.pl ../processed_data/subtask_port/analysis/sjtu_wifi_merge.pcap.ua.txt.bz2.os.txt ../processed_data/subtask_port/text/sjtu_wifi_merge.pcap.txt.bz2
##    perl detect_tethering_multifiles.sjtu_wifi.pl ../processed_data/subtask_port/analysis/sjtu_wifi_merge.pcap.ua.txt.bz2.os.txt ../processed_data/subtask_gen_trace/sjtu_wifi_merge.pcap.txt.bz2
##    perl detect_tethering_multifiles.sjtu_wifi.pl ../processed_data/subtask_port/analysis/sjtu_wifi_merge.pcap.ua.txt.bz2.os.txt ../processed_data/subtask_gen_trace/tmp.txt.bz2
##
##########################################

use lib "../utils";

use strict;
use Tethering;
use IPTool;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 0;
my $DEBUG2 = 1;     ## program flow
my $DEBUG3 = 1;     ## results
my $DEBUG4 = 0;     ## each heuristic
my $DEBUG5 = 0;     ## os file


#############
# Constants
#############
my $MIN_NUM_PKTS = 0;


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_port/text";
my $output_dir = "../processed_data/subtask_detect/tether_ips";
my $account_dir = "/u/yichao/anomaly_compression/data/sjtu_wifi/RADIUS";
my $tmp_dir = "../processed_data/subtask_detect/tmp";

my $output_file = "results.txt";
open FH_OUT, ">$output_dir/$output_file" or die $!;

my @file_names;
my @file_dirs;

my $FIX_DST      = 0;               ## 1 to fix the TCP dst
my $FIX_DST_ADDR = "192.168.5.67";
my $FIX_SRC      = 1;               ## 1 to fix the TCP src
my $FIX_SRC_ADDR = "^111\.";

# my %account_info = ();
# my %os_info = ();
my %ip_info = ();
my %tethered_ips = ();
my %non_tethered_ips = ();
my $heuristic;


#############
# check input
#############
print "check input\n" if($DEBUG2);
# if(@ARGV != 1) {
#     print "wrong number of input\n";
#     exit;
# }
my $os_file = shift @ARGV;
my @fullpaths = @ARGV;
print "os file: $os_file\n";
print "input files: \n  ".join("\n  ", @fullpaths)."\n";
# exit;


#############
## Read RADIUS account data
#############
# print "Read RADIUS account data: $account_dir\n" if($DEBUG2);
# %account_info = IPTool::read_account_info($account_dir);
# print "  size=".scalar(keys %{ $account_info{USER_IP} })."\n" if($DEBUG1);



#############
# read OS
#############
# print "start to read os\n" if($DEBUG2);

# open FH, "$os_file" or die $_;
# while (<FH>) {
#     chomp;
#     my ($this_ip, $this_os) = split(/, /, $_);
#     # next unless(exists $account_info{USER_IP}{$this_ip});
#     print "  '$this_ip': '$this_os'\n" if($DEBUG5);

#     $os_info{$this_ip} = $this_os;

# }
# close FH;



#############
## read input files
#############
print "start to read input files\n" if($DEBUG2);
foreach my $tmp (@fullpaths) {
    if($tmp =~ /(.*)\/(.*)/) {
        my $file_name = $2;
        my $file_dir  = $1;

        push(@file_names, $file_name);
        push(@file_dirs,  $file_dir);


        #############
        ## Read the file
        #############
        ## TCP Timestamp
        print "Start to read TCP Timestamp data\n" if($DEBUG2);

        open FH, "$file_dir/$file_name" or die $!."\n$file_dir/$file_name\n";
        # open FH, "bzcat $file_dir/$file_name |" or die $!."\n$file_dir/$file_name\n";
        while(<FH>) {
            chomp;
            next if($_ =~ /Processed/); ## used to ignore the last line in the input file

            my ($frame_num, $time, $frame_len, $ip_src_list, $ip_dst_list, $ip_id_list, $ip_ttl_list, $ip_flag_df_list, $ip_flag_rb_list, $ip_flag_sf_list, $ip_opt_len_list, $ip_opt_type_number_list, $ip_opt_ext_sec_add_sec_info_list, $ip_opt_id_number_list, $ip_opt_mtu_list, $ip_opt_ohc_list, $ip_opt_padding_list, $ip_opt_ptr_list, $ip_opt_qs_rate_list, $ip_opt_qs_ttl_list, $ip_opt_qs_unused_list, $ip_opt_sec_cl_list, $ip_opt_sid_list, $ip_dsfield_ce_list, $ip_dsfield_dscp_list, $ip_dsfield_ecn_list, $ip_dsfield_ect_list, $ip_tos_cost_list, $ip_tos_delay_list, $ip_tos_precedence_list, $ip_tos_reliability_list, $ip_tos_throughput_list, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_seq, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_ts_val, $tcp_ts_ecr, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports, $ua) = split(/\|/, $_);
            $time += 0; $frame_len += 0; $udp_sport += 0; $udp_dport += 0; $tcp_sport += 0; $tcp_dport += 0;

            ## deal with IPs
            my @tmp = split(/,/, $ip_id_list); my $ip_id = hex($tmp[-1]);
            @tmp = split(/,/, $ip_ttl_list); my $ip_ttl = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_flag_df_list); my $ip_flag_df = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_flag_rb_list); my $ip_flag_rb = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_flag_sf_list); my $ip_flag_sf = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_len_list); my $ip_opt_len = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_type_number_list); my $ip_opt_type_number = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_ext_sec_add_sec_info_list); my $ip_opt_ext_sec_add_sec_info = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_id_number_list); my $ip_opt_id_number = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_mtu_list); my $ip_opt_mtu = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_ohc_list); my $ip_opt_ohc = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_padding_list); my $ip_opt_padding = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_ptr_list); my $ip_opt_ptr = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_qs_rate_list); my $ip_opt_qs_rate = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_qs_ttl_list); my $ip_opt_qs_ttl = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_qs_unused_list); my $ip_opt_qs_unused = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_sec_cl_list); my $ip_opt_sec_cl = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_opt_sid_list); my $ip_opt_sid = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_dsfield_ce_list); my $ip_dsfield_ce = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_dsfield_dscp_list); my $ip_dsfield_dscp = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_dsfield_ecn_list); my $ip_dsfield_ecn = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_dsfield_ect_list); my $ip_dsfield_ect = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_tos_cost_list); my $ip_tos_cost = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_tos_delay_list); my $ip_tos_delay = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_tos_precedence_list); my $ip_tos_precedence = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_tos_reliability_list); my $ip_tos_reliability = $tmp[-1] + 0;
            @tmp = split(/,/, $ip_tos_throughput_list); my $ip_tos_throughput = $tmp[-1] + 0;

            @tmp = split(/,/, $ip_src_list); my $ip_src = $tmp[-1];
            @tmp = split(/,/, $ip_dst_list); my $ip_dst = $tmp[-1];
            
            $ip_flag_df += 0; $ip_flag_rb += 0; $ip_flag_sf += 0; 
            $ip_opt_len += 0; $ip_opt_type_number += 0; $ip_opt_ext_sec_add_sec_info += 0; $ip_opt_id_number += 0; $ip_opt_mtu += 0; $ip_opt_ohc += 0; $ip_opt_padding += 0; $ip_opt_ptr += 0; $ip_opt_qs_rate += 0; $ip_opt_qs_ttl += 0; $ip_opt_qs_unused += 0; $ip_opt_sec_cl += 0; $ip_opt_sid += 0; 
            $ip_dsfield_ce += 0; $ip_dsfield_dscp += 0; $ip_dsfield_ecn += 0; $ip_dsfield_ect += 0;
            $ip_tos_cost += 0; $ip_tos_delay += 0; $ip_tos_precedence += 0; $ip_tos_reliability += 0; $ip_tos_throughput += 0;
            
            $tcp_flag_ack += 0; $tcp_flag_cwr += 0; $tcp_flag_ecn += 0; $tcp_flag_fin += 0; $tcp_flag_ns += 0; $tcp_flag_push += 0; $tcp_flag_res += 0; $tcp_flag_reset += 0; $tcp_flag_syn += 0; $tcp_flag_urg += 0;
            $tcp_len += 0; $tcp_opt_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0; $tcp_bytes_in_flight += 0; $tcp_win_size_scalefactor += 0; $tcp_win_size += 0; $tcp_pdu_size += 0; $tcp_reused_ports += 0; $tcp_seq += 0;


            next if($tcp_sport == 0); ## udp
            # next unless(exists $os_info{$ip_src});
            # next unless(exists $account_info{USER_IP}{$ip_src});
            next if($FIX_SRC and (!($ip_src =~ /$FIX_SRC_ADDR/ )));
            next if($FIX_DST and (!($ip_dst =~ /$FIX_DST_ADDR/)));


            ## check if it's a reordering / retransmission
            next if(exists $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{SEQ} and $tcp_seq < $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{SEQ}[-1]);
            ## check if it's a duplicate
            next if(exists $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{TX_TIME} and 
                $tcp_ts_val == $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{TX_TIME}[-1] and 
                $time == $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{RX_TIME}[-1] and 
                $tcp_seq == $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{SEQ}[-1]);


            push( @{ $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{SEQ}     }, $tcp_seq);
            $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{TTL}{$ip_ttl} = 1;

            if($tcp_ts_val != 0) {
                push( @{ $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{TX_TIME} }, $tcp_ts_val);
                push( @{ $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{RX_TIME} }, $time);
            
                $ip_info{IP}{$ip_src}{ALL_FLOW}{RX_TIME}{$time}{TX_TIME} = $tcp_ts_val;
            }

            if($ip_id != 0) {
                push( @{ $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{IP_ID} }, $ip_id);
                push( @{ $ip_info{IP}{$ip_src}{ALL_FLOW}{IP_ID} }, $ip_id);
            }
            
            $ip_info{IP}{$ip_src}{ALL_FLOW}{CNT} ++;

            ######################
            ## IP
            ######################
            $ip_info{IP}{$ip_src}{ALL_FLOW}{TTL}{$ip_ttl} = 1;
            
            $ip_info{IP}{$ip_src}{ALL_FLOW}{DF} ++ if($ip_flag_df == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{RB} ++ if($ip_flag_rb == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{SF} ++ if($ip_flag_sf == 1);

            $ip_info{IP}{$ip_src}{ALL_FLOW}{OPT_LEN}{$ip_opt_len} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{OPT_NUM}{$ip_opt_type_number} ++;

            $ip_info{IP}{$ip_src}{ALL_FLOW}{DS_CE}{$ip_dsfield_ce} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{DS_DSCP}{$ip_dsfield_dscp} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{DS_ECN}{$ip_dsfield_ecn} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{DS_ECT}{$ip_dsfield_ect} ++;

            $ip_info{IP}{$ip_src}{ALL_FLOW}{TOS_COST}{$ip_tos_cost} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{TOS_DELAY}{$ip_tos_delay} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{TOS_PRECEDENCE}{$ip_tos_precedence} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{TOS_RELIABILITY}{$ip_tos_reliability} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{TOS_TPUT}{$ip_tos_throughput} ++;

            ######################
            ## TCP
            ######################
            $ip_info{IP}{$ip_src}{ALL_FLOW}{ACK} ++   if($tcp_flag_ack == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{CWR} ++   if($tcp_flag_cwr == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{ECN} ++   if($tcp_flag_ecn == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{FIN} ++   if($tcp_flag_fin == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{NS} ++    if($tcp_flag_ns == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{PUSH} ++  if($tcp_flag_push == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{RES} ++   if($tcp_flag_res == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{RESET} ++ if($tcp_flag_reset == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{SYN} ++   if($tcp_flag_syn == 1);
            $ip_info{IP}{$ip_src}{ALL_FLOW}{URG} ++   if($tcp_flag_urg == 1);

            $ip_info{IP}{$ip_src}{ALL_FLOW}{LEN}{$tcp_len} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{LEN_SUM} += $tcp_len;
            
            if($tcp_opt_kind ne "") {
                my @kinds = split(/,/, $tcp_opt_kind);
                foreach my $kind (@kinds) {
                    $kind += 0;
                    $ip_info{IP}{$ip_src}{ALL_FLOW}{OPT_KIND}{$kind} ++;
                    $ip_info{IP}{$ip_src}{CONN}{"$tcp_sport.$ip_dst.$tcp_dport"}{OPT_KIND}{$kind} ++;
                }
                $ip_info{IP}{$ip_src}{ALL_FLOW}{NUM_OPT_KIND}{scalar(@kinds)} ++;
            }
            else {
                $ip_info{IP}{$ip_src}{ALL_FLOW}{NUM_OPT_KIND}{0} ++;
            }

            $ip_info{IP}{$ip_src}{ALL_FLOW}{OPT_LEN}{$tcp_opt_len} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{OPT_LEN_SUM} += $tcp_opt_len;

            $ip_info{IP}{$ip_src}{ALL_FLOW}{FLIGHT}{TIME}{$time}{FLIGHT} = $tcp_bytes_in_flight;
            
            $ip_info{IP}{$ip_src}{ALL_FLOW}{WIN_SCALE}{$tcp_win_size_scalefactor} ++ if($tcp_win_size_scalefactor >= 0); 
            $ip_info{IP}{$ip_src}{ALL_FLOW}{WIN_SIZE}{$tcp_win_size} ++;

            $ip_info{IP}{$ip_src}{ALL_FLOW}{PDU_SIZE}{$tcp_pdu_size} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{CONT}{$tcp_cont} ++;
            $ip_info{IP}{$ip_src}{ALL_FLOW}{REUSED_PORT}{$tcp_reused_ports} ++;
            
        }
    }    
}

# print "  - file: $file_dir/$file_name\n" if($DEBUG2);
# exit;



#############
## Check Heuristics
#############
print "Check Heuristics\n" if($DEBUG2);
foreach my $this_ip (sort {$a cmp $b} (keys %{ $ip_info{IP} })) {
    # print "\n  - $this_ip (".$os_info{$this_ip}.")\n" if($DEBUG4);
    print "\n  - $this_ip\n" if($DEBUG4);
    print "$this_ip" if($DEBUG3);
    print FH_OUT "$this_ip" if($DEBUG3);
    my $cnt_heuristics = 0;
    my $cnt_detect = 0;



    #############
    ## Check TTL Heuristic
    #############
    my @ttls = (keys %{ $ip_info{IP}{$this_ip}{ALL_FLOW}{TTL} });
    
    $heuristic = "ttl_num";
    $cnt_heuristics ++;
    my $if_tether = Tethering::check_ttl_num(\@ttls);
    print "  $heuristic: $if_tether (".join(",", @ttls).")\n" if($DEBUG4);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        $cnt_detect ++;
        print ", 1" if($DEBUG3);
        print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        print ", 0" if($DEBUG3);
        print FH_OUT ", 0" if($DEBUG3);
    }


    my $gap_threshold = 5;
    $heuristic = "gap_ttl_num.gap$gap_threshold";
    $cnt_heuristics ++;
    $if_tether = Tethering::check_gap_ttl_num(\@ttls, $gap_threshold);
    print "  $heuristic: $if_tether\n" if($DEBUG4);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        $cnt_detect ++;
        print ", 1" if($DEBUG3);
        print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        print ", 0" if($DEBUG3);
        print FH_OUT ", 0" if($DEBUG3);
    }


    #############
    ## Check TCP Timestamp monotonicity
    #############
    my @tx_times;
    my @rx_times;
    foreach my $this_rx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{ALL_FLOW}{RX_TIME} })) {
        push(@rx_times, $this_rx_time);
        push(@tx_times, $ip_info{IP}{$this_ip}{ALL_FLOW}{RX_TIME}{$this_rx_time}{TX_TIME});
    }

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
        print "  $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            $cnt_detect ++;
            print ", 1" if($DEBUG3);
            print FH_OUT ", 1" if($DEBUG3);

            # if($DEBUG4) {
            #     open FH_TMP, "> $tmp_dir/$this_ip.$heuristic.txt" or die $!;
            #     foreach my $i (0 .. @rx_times-1) {
            #         print FH_TMP "".$rx_times[$i].", ".$tx_times[$i]."\n";
            #     }
            #     close FH_TMP;
            # }
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            print ", 0" if($DEBUG3);
            print FH_OUT ", 0" if($DEBUG3);
        }


        if($DEBUG4) {
            open FH_TMP, "> $tmp_dir/$this_ip.$heuristic.txt" or die $!;
            foreach my $i (0 .. @rx_times-1) {
                print FH_TMP "".$rx_times[$i].", ".$tx_times[$i]."\n";
            }
            close FH_TMP;
        }
    }


    #############
    ## Check Window Scale
    #############
    my %os = ();
    
    $heuristic = "win_scale";
    $cnt_heuristics ++;
    my $win_scales_ref = \%{ $ip_info{IP}{$this_ip}{ALL_FLOW}{WIN_SCALE} };
    my ($if_tether, $tmp_os_ref) = Tethering::check_win_scale($win_scales_ref);
    my %tmp = (%os, %$tmp_os_ref);
    %os = %tmp;

    print "  $heuristic: $if_tether (".join(",", (keys %os)).")\n" if($DEBUG4);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        $cnt_detect ++;
        print ", 1" if($DEBUG3);
        print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        print ", 0" if($DEBUG3);
        print FH_OUT ", 0" if($DEBUG3);
    }

    


    #############
    ## Check TCP Timestamp Option (kind = 8)
    ##   $ip_info{IP}{$ip_src}{ALL_FLOW}{OPT_KIND}{$kind} 
    #############
    $heuristic = "timestamp_option";
    $cnt_heuristics ++;
    
    my $opt_kind_ref = \%{ $ip_info{IP}{$this_ip}{ALL_FLOW}{OPT_KIND} };
    my $opt_kind_flow_erf = \%{ $ip_info{IP}{$this_ip} };

    my $tmp_os_ref = Tethering::check_tcp_timestamp_option($opt_kind_ref, $opt_kind_flow_erf);
    my %tmp = (%os, %$tmp_os_ref);
    %os = %tmp;
    my $if_tether = 0;
    $if_tether = 1 if(scalar(keys %os) > 1);
    print "  $heuristic: $if_tether (".join(",", (keys %os)).")\n" if($DEBUG4);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        $cnt_detect ++;
        print ", 1" if($DEBUG3);
        print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        print ", 0" if($DEBUG3);
        print FH_OUT ", 0" if($DEBUG3);
    }

    
    #############
    ## Check IP ID monotonicity
    #############
    my @ip_ids = ();
    my $ip_ids_flow_ref = \%{ $ip_info{IP}{$this_ip} };

    if(exists $ip_info{IP}{$this_ip}{ALL_FLOW}{IP_ID}) {
        @ip_ids = @{ $ip_info{IP}{$this_ip}{ALL_FLOW}{IP_ID} };
    }
    else {
        @ip_ids = (0);
    }

    
    $heuristic = "ip_id_monotonicity";
    $cnt_heuristics ++;
    my $tmp_os_ref = Tethering::check_ip_id_monotonicity(\@ip_ids, $ip_ids_flow_ref);
    my %tmp = (%os, %$tmp_os_ref);
    %os = %tmp;
    my $if_tether = 0;
    $if_tether = 1 if(scalar(keys %os) > 1);
    print "  $heuristic: $if_tether (".join(",", (keys %os)).")\n" if($DEBUG4);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        $cnt_detect ++;
        print ", 1" if($DEBUG3);
        print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        print ", 0" if($DEBUG3);
        print FH_OUT ", 0" if($DEBUG3);
    }

    if($DEBUG4) {
        open FH_TMP, "> $tmp_dir/$this_ip.$heuristic.txt" or die $!;
        print FH_TMP "".join("\n", @ip_ids)."\n";
        close FH_TMP;
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
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_flow_frequency_first_last_span($flows_ref, $freq_span_threshold);
        print "  $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            $cnt_detect ++;
            print ", 1" if($DEBUG3);
            print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            print ", 0" if($DEBUG3);
            print FH_OUT ", 0" if($DEBUG3);
        }
    }

    
    ## 2.
    $heuristic = "freq_first_last_enu";
    $cnt_heuristics ++;
    $if_tether = Tethering::check_flow_frequency_first_last_enumeration($flows_ref, \@freqs);
    print "  $heuristic: $if_tether\n" if($DEBUG4);

    if($if_tether >= 1) {
        $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        $cnt_detect ++;
        print ", 1" if($DEBUG3);
        print FH_OUT ", 1" if($DEBUG3);
    }
    else {
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        print ", 0" if($DEBUG3);
        print FH_OUT ", 0" if($DEBUG3);
    }


    ## 3. 
    @freq_span_thresholds = (1, 10, 50);
    my @rx_time_gaps      = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        foreach my $freq_span_threshold (@freq_span_thresholds) {
            $heuristic = "freq_median_span.span$freq_span_threshold.rx_gap$rx_time_gap";
            $cnt_heuristics ++;
            my $if_tether = Tethering::check_flow_frequency_median_span($flows_ref, $rx_time_gap, $freq_span_threshold);
            print "  $heuristic: $if_tether\n" if($DEBUG4);

            if($if_tether >= 1) {
                $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
                $cnt_detect ++;
                print ", 1" if($DEBUG3);
                print FH_OUT ", 1" if($DEBUG3);
            }
            else {
                $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
                print ", 0" if($DEBUG3);
                print FH_OUT ", 0" if($DEBUG3);
            }
        }
    }


    ## 4.
    @rx_time_gaps = (0, 1, 5);
    foreach my $rx_time_gap (@rx_time_gaps) {
        $heuristic = "freq_median_enu.rx_gap$rx_time_gap";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_flow_frequency_median_enumeration($flows_ref, \@freqs, $rx_time_gap);
        print "  $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            $cnt_detect ++;
            print ", 1" if($DEBUG3);
            print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            print ", 0" if($DEBUG3);
            print FH_OUT ", 0" if($DEBUG3);
        }
    }


    ## 5. 
    my @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "freq_enu_boot.boot_span$boot_time_span_thresh";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_flow_frequency_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);
        print "  $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            $cnt_detect ++;
            print ", 1" if($DEBUG3);
            print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            print ", 0" if($DEBUG3);
            print FH_OUT ", 0" if($DEBUG3);
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
        print "  $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            $cnt_detect ++;
            print ", 1" if($DEBUG3);
            print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            print ", 0" if($DEBUG3);
            print FH_OUT ", 0" if($DEBUG3);
        }
    }

    
    ## 2.
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_first_last_enu.span$boot_time_span_thresh";
        $cnt_heuristics ++;
        $if_tether = Tethering::check_boot_time_first_last_enumeration($flows_ref, \@freqs, $boot_time_span_thresh);
        print "  $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            $cnt_detect ++;
            print ", 1" if($DEBUG3);
            print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            print ", 0" if($DEBUG3);
            print FH_OUT ", 0" if($DEBUG3);
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
            print "  $heuristic: $if_tether\n" if($DEBUG4);

            if($if_tether >= 1) {
                $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
                $cnt_detect ++;
                print ", 1" if($DEBUG3);
                print FH_OUT ", 1" if($DEBUG3);
            }
            else {
                $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
                print ", 0" if($DEBUG3);
                print FH_OUT ", 0" if($DEBUG3);
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
            print "  $heuristic: $if_tether\n" if($DEBUG4);

            if($if_tether >= 1) {
                $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
                $cnt_detect ++;
                print ", 1" if($DEBUG3);
                print FH_OUT ", 1" if($DEBUG3);
            }
            else {
                $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
                print ", 0" if($DEBUG3);
                print FH_OUT ", 0" if($DEBUG3);
            }
        }
    }


    ## 5. 
    @boot_time_span_threshs = (99999, 100, 10, 5, 1);
    foreach my $boot_time_span_thresh (@boot_time_span_threshs) {
        $heuristic = "boot_time_enu.span$boot_time_span_thresh";
        $cnt_heuristics ++;
        my $if_tether = Tethering::check_boot_time_enumeration_boot_span($flows_ref, \@freqs, $boot_time_span_thresh);
        print "  $heuristic: $if_tether\n" if($DEBUG4);

        if($if_tether >= 1) {
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            $cnt_detect ++;
            print ", 1" if($DEBUG3);
            print FH_OUT ", 1" if($DEBUG3);
        }
        else {
            $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
            print ", 0" if($DEBUG3);
            print FH_OUT ", 0" if($DEBUG3);
        }
    }

    # print "$this_ip, $cnt_detect, $cnt_heuristics\n" if($DEBUG3);
    # print ", ".$os_info{$this_ip}.":".join(", ", (keys %os))."\n" if($DEBUG3);
    print ", ".join(", ", (keys %os))."\n" if($DEBUG3);
    print FH_OUT ", ".join(", ", (keys %os))."\n" if($DEBUG3);
}

close FH_OUT;


#############
## Print out detection results
#############
print "\nPrint out tethering results\n" if($DEBUG2);

foreach my $this_heuristic (sort {$a cmp $b} (keys %{ $tethered_ips{HEURISTIC} })) {
    print "  - $this_heuristic: ".scalar(keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} }))."\n" if($DEBUG2);

    ## Tethered IPs
    # open FH, "> $output_dir/$file_name.$this_heuristic.txt" or die $!;
    # print FH join("\n", (keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n";
    # print join("\n", (keys (%{ $tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n" if($DEBUG1);
    # close FH;
}

print "Print out non-tethering results\n" if($DEBUG2);
foreach my $this_heuristic (sort {$a cmp $b} (keys %{ $non_tethered_ips{HEURISTIC} })) {
    print "  - $this_heuristic: ".scalar(keys (%{ $non_tethered_ips{HEURISTIC}{$this_heuristic}{IP} }))."\n" if($DEBUG2);

    ## Non-tethered IPs
    # open FH, "> $output_dir/$file_name.$this_heuristic.nontether.txt" or die $!;
    # print FH join("\n", (keys (%{ $non_tethered_ips{HEURISTIC}{$this_heuristic}{IP} })))."\n";
    # close FH;
}

