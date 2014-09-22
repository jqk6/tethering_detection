#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.15 @ UT Austin
##
## - input: 
##   1. os file
##   2. input trace file
##    
##
##  e.g.
##    perl gen_trace.sjtu_wifi.pl 0 ../processed_data/subtask_port/analysis/sjtu_wifi_merge.pcap.ua.txt.bz2.os.txt ../processed_data/subtask_gen_trace/sjtu_wifi_merge.pcap.txt.bz2
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
my $DEBUG5 = 1;     ## os file


#############
# Constants
#############
my $non_tether_net = "111.180";
my $tether_net     = "111.190";
my $init_time_range = 120;
my $num_dup_non_tether = 8;
my $num_clients_per_tether = 2;


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_port/text";
my $output_dir = "../processed_data/subtask_gen_trace";
my $mapping_dir = "../processed_data/subtask_gen_trace/mapping";
my $account_dir = "/u/yichao/anomaly_compression/data/sjtu_wifi/RADIUS";

my @file_names;
my @file_dirs;

my $FIX_DST      = 0;               ## 1 to fix the TCP dst
my $FIX_DST_ADDR = "";
my $FIX_SRC      = 1;               ## 1 to fix the TCP src
my $FIX_SRC_ADDR = "^111\.18";

# my %account_info = ();
my %os_info = ();
my %ip_info = ();
my %ip_map  = ();
my %tethered_ips = ();
my %non_tethered_ips = ();
my $heuristic;

my $num_non_tether = 0;
my $num_tether     = 0;


#############
# check input
#############
print "check input\n" if($DEBUG2);
# if(@ARGV != 1) {
#     print "wrong number of input\n";
#     exit;
# }
my $exp = shift @ARGV;
my $os_file = shift @ARGV;
my @fullpaths = @ARGV;

$exp += 0;

print "exp: $exp\n";
print "os file: $os_file\n";
print "input files: \n  ".join("\n  ", @fullpaths)."\n";
# exit;

my $output_file = "sjtu_wifi_merge.exp$exp.txt";
my $mapping_file = "sjtu_wifi_merge.exp$exp.txt";
open FH_MAP, ">$mapping_dir/$mapping_file" or die $!;
srand($exp);


#############
## Read RADIUS account data
#############
# print "Read RADIUS account data: $account_dir\n" if($DEBUG2);
# %account_info = IPTool::read_account_info($account_dir);
# print "  size=".scalar(keys %{ $account_info{USER_IP} })."\n" if($DEBUG2);



#############
# read OS
#############
print "start to read os\n" if($DEBUG2);

open FH, "$os_file" or die $_;
while (<FH>) {
    chomp;
    my ($this_ip, $this_os) = split(/, /, $_);
    # next unless(exists $account_info{USER_IP}{$this_ip});
    print "  '$this_ip': '$this_os'\n" if($DEBUG5);

    $os_info{$this_ip} = $this_os;

}
close FH;


#############
## replicate tether IPs
#############
my $num_win_win = 5;
for my $i (1 .. $num_win_win) {
    my $tmp_ip      = "111.186.62.22"; ## Windows
    my $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

    $tmp_ip      = "111.186.61.10"; ## Windows
    $mapped_ip   = "$tether_net.0.$num_tether";
    $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
    $num_tether ++;
}

my $num_win_android = 3;
for my $i (1 .. $num_win_android) {
    my $tmp_ip      = "111.186.62.14"; ## Windows
    my $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

    $tmp_ip      = "111.186.63.92"; ## Android
    $mapped_ip   = "$tether_net.0.$num_tether";
    $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
    $num_tether ++;
}

my $num_win_apple = 2;
for my $i (1 .. $num_win_apple) {
    my $tmp_ip      = "111.186.62.14"; ## Windows
    my $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

    $tmp_ip      = "111.186.10.11"; ## Apple
    $mapped_ip   = "$tether_net.0.$num_tether";
    $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
    $num_tether ++;
}

my $num_android_android = 6;
for my $i (1 .. $num_android_android) {
    my $tmp_ip      = "111.186.1.5"; ## Android
    my $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

    $tmp_ip      = "111.186.0.16"; ## Android
    $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
    $num_tether ++;
}
for my $i (1 .. $num_android_android) {
    my $tmp_ip      = "111.186.62.27"; ## Android
    my $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

    $tmp_ip      = "111.186.1.5"; ## Android
    $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
    $num_tether ++;
}
# my @android_ips = ("111.186.62.27", "111.186.62.47", "111.186.63.92", "111.186.61.9", "111.186.0.16", "111.186.61.4", "111.186.1.5");
# for my $i (0 .. @android_ips-1) {
#     for my $j ($i .. @android_ips-1) {
#         my $tmp_ip      = $android_ips[$i];
#         my $mapped_ip   = "$tether_net.0.$num_tether";
#         my $mapped_time = rand($init_time_range);
#         print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
#         push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
#         push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

#         my $tmp_ip      = $android_ips[$j];
#         $mapped_ip   = "$tether_net.0.$num_tether";
#         my $mapped_time = rand($init_time_range);
#         print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
#         push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
#         push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
#         $num_tether ++;
#     }
# }


my $num_android_apple = 9;
for my $i (1 .. $num_android_apple) {
    my $tmp_ip      = "111.186.10.11"; ## Apple
    my $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

    $tmp_ip      = "111.186.1.5"; ## Android
    $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
    $num_tether ++;
}

my $num_apple_apple = 6;
for my $i (1 .. $num_apple_apple) {
    my $tmp_ip      = "111.186.63.10"; ## Apple
    my $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);

    $tmp_ip      = "111.186.62.35"; ## Apple
    $mapped_ip   = "$tether_net.0.$num_tether";
    my $mapped_time = rand($init_time_range);
    print FH_MAP "$tmp_ip, $mapped_ip, ".$os_info{$tmp_ip}."\n";
    push(@{ $ip_map{$tmp_ip}{IP} }, $mapped_ip);
    push(@{ $ip_map{$tmp_ip}{TIME} }, $mapped_time);
    $num_tether ++;
}



#############
## read input files
#############
print "start to read input files\n" if($DEBUG2);

my %buf = ();
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

        # open FH, "$file_dir/$file_name" or die $!."\n$file_dir/$file_name\n";
        open FH, "bzcat $file_dir/$file_name |" or die $!."\n$file_dir/$file_name\n";
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
            next unless(exists $os_info{$ip_src});
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


            ##################
            ## replicate IPs
            ##################
            unless(exists $ip_map{$ip_src}) {
                for (my $i = 0; $i < $num_dup_non_tether; $i++) {
                    my $mapped_ip = "$non_tether_net.0.$num_non_tether";
                    my $mapped_time = rand($init_time_range);
                    
                    push(@{ $ip_map{$ip_src}{IP} }, $mapped_ip);
                    push(@{ $ip_map{$ip_src}{TIME} }, $mapped_time);
                    $ip_map{$ip_src}{SHIFT}{$mapped_ip} = $time - $mapped_time;

                    print FH_MAP "$ip_src, $mapped_ip, $mapped_time, ".$ip_map{$ip_src}{SHIFT}{$mapped_ip}.", ".$os_info{$ip_src}."\n";

                    $num_non_tether ++;
                }

                # ## replicate tether IPs
                # for (my $i = 0; $i < 1; $i++) {
                #     my $real_tether_ip = int($num_tether / $num_clients_per_tether);
                #     my $mapped_ip = "$tether_net.0.$real_tether_ip";
                #     my $mapped_time = rand($init_time_range);

                #     push(@{ $ip_map{$ip_src}{IP} }, $mapped_ip);
                #     push(@{ $ip_map{$ip_src}{TIME} }, $mapped_time);
                #     $ip_map{$ip_src}{SHIFT}{$mapped_ip} = $time - $mapped_time;

                #     print FH_MAP "$ip_src, $mapped_ip, $mapped_time, ".$ip_map{$ip_src}{SHIFT}{$mapped_ip}.", ".$os_info{$ip_src}."\n";

                #     $num_tether ++;
                # }
            }
            

            ## start to replicate
            foreach my $i (0 .. @{ $ip_map{$ip_src}{IP} }) {
                my $mapped_ip = $ip_map{$ip_src}{IP}[$i];
                my $mapped_time = $ip_map{$ip_src}{TIME}[$i];
                my $shift_time = $time - $ip_map{$ip_src}{SHIFT}{$mapped_ip};

                unless (exists $ip_map{$ip_src}{SHIFT}{$mapped_ip}) {
                    $ip_map{$ip_src}{SHIFT}{$mapped_ip} = $time - $mapped_time;
                }

                # print FH_OUT join("|", ($frame_num, $shift_time, $frame_len, $mapped_ip, $ip_dst, $ip_id, $ip_ttl, $ip_flag_df, $ip_flag_rb, $ip_flag_sf, $ip_opt_len, $ip_opt_type_number, $ip_opt_ext_sec_add_sec_info, $ip_opt_id_number, $ip_opt_mtu, $ip_opt_ohc, $ip_opt_padding, $ip_opt_ptr, $ip_opt_qs_rate, $ip_opt_qs_ttl, $ip_opt_qs_unused, $ip_opt_sec_cl, $ip_opt_sid, $ip_dsfield_ce, $ip_dsfield_dscp, $ip_dsfield_ecn, $ip_dsfield_ect, $ip_tos_cost, $ip_tos_delay, $ip_tos_precedence, $ip_tos_reliability, $ip_tos_throughput, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_seq, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_ts_val, $tcp_ts_ecr, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports, $ua))."\n";
                my $tmp = join("|", ($frame_num, $shift_time, $frame_len, $mapped_ip, $ip_dst, $ip_id, $ip_ttl, $ip_flag_df, $ip_flag_rb, $ip_flag_sf, $ip_opt_len, $ip_opt_type_number, $ip_opt_ext_sec_add_sec_info, $ip_opt_id_number, $ip_opt_mtu, $ip_opt_ohc, $ip_opt_padding, $ip_opt_ptr, $ip_opt_qs_rate, $ip_opt_qs_ttl, $ip_opt_qs_unused, $ip_opt_sec_cl, $ip_opt_sid, $ip_dsfield_ce, $ip_dsfield_dscp, $ip_dsfield_ecn, $ip_dsfield_ect, $ip_tos_cost, $ip_tos_delay, $ip_tos_precedence, $ip_tos_reliability, $ip_tos_throughput, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_seq, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_ts_val, $tcp_ts_ecr, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports, $ua))."\n";
                $buf{$shift_time}{$tmp} = 1;
            }
            
        }
    }    
}
close FH_MAP;

print "non tether clients: $num_non_tether\n";
print "tether clients: $num_tether\n";


open FH_OUT, "> $output_dir/$output_file" or die $!;
foreach my $time (sort {$a <=> $b} (keys %buf) ) {
    foreach my $buf (keys %{ $buf{$time} }) {
        print FH_OUT $buf;
    }
}
close FH_OUT;




#############
## compression
#############
# print "compression\n" if($DEBUG2);
# my $cmd = "bzip2 $output_dir/$output_file";
# `$cmd`;
