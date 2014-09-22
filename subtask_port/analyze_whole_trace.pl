#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.14 @ UT Austin
##
## - input:
##
## - output:
##
## - e.g.
##   perl analyze_whole_trace.pl 111.18 sjtu_wifi_merge.pcap.txt.bz2 sjtu_wifi_merge.pcap.ua.txt.bz2.os.txt
##########################################

use strict;
use lib "../utils";

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print output
my $DEBUG4 = 0; ## parse port
my $DEBUG5 = 0; ## TCP flag
my $DEBUG6 = 0; ## IP
my $DEBUG7 = 1; ## read OS


#############
# Constants
#############
my $TOP_N = 10;


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_port/text";
my $output_dir = "../processed_data/subtask_port/analysis";
my $figure_dir = "../processed_data/subtask_port/analysis_figures";

my $gnuplot_port = "plot_port";
my $gnuplot_dist = "plot_dist";

my $ip;
my $filename;
my $os_file;

my %port_info = ();  ## PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
my %ip_info   = ();  ## [CNT | DF | RB | SF]
                     ## [OPT_LEN | OPT_NUM | DS_CE | DS_DSCP | DS_ECN | DS_ECT] 
my %tcp_info  = ();  ## [CNT | ACK | CWR | ECN | FIN | NS | PUSH | RES | RESET | SYN | URG]
                     ## [LEN | OPT_KIND | OPT_LEN | FLIGHT | WIN_SCALE | WIN_SIZE | PDU_SIZE | CONT | REUSED_PORT] - value - count
my %os_info   = ();  ## IP - OS


#############
# check input
#############
if(@ARGV != 3) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$ip       = $ARGV[0];
$filename = $ARGV[1];
$os_file  = $ARGV[2];
if($DEBUG2) {
    print "ip  : $ip\n";
    print "file: $filename\n";
    print "os  : $os_file\n\n";
}


#############
# Main starts
#############

#############
# read OS
#############
print "start to read os\n" if($DEBUG2);

open FH, "$output_dir/$os_file" or die $_;
while (<FH>) {
    chomp;
    my ($this_ip, $this_os) = split(/, /, $_);
    print "  '$this_ip': '$this_os'\n" if($DEBUG7);

    $os_info{$this_ip} = $this_os;

}
close FH;


#############
# read trace file
#############
print "start to read trace file\n" if($DEBUG2);

# open FH, "$input_dir/$filename" or die $!;
open FH, "bzcat $input_dir/$filename |" or die $!;
while(<FH>) {
    chomp;
    print "> $_\n" if($DEBUG4);

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
    
    $ip_flag_df += 0; $ip_flag_rb += 0; $ip_flag_sf += 0; 
    $ip_opt_len += 0; $ip_opt_type_number += 0; $ip_opt_ext_sec_add_sec_info += 0; $ip_opt_id_number += 0; $ip_opt_mtu += 0; $ip_opt_ohc += 0; $ip_opt_padding += 0; $ip_opt_ptr += 0; $ip_opt_qs_rate += 0; $ip_opt_qs_ttl += 0; $ip_opt_qs_unused += 0; $ip_opt_sec_cl += 0; $ip_opt_sid += 0; 
    $ip_dsfield_ce += 0; $ip_dsfield_dscp += 0; $ip_dsfield_ecn += 0; $ip_dsfield_ect += 0;
    $ip_tos_cost += 0; $ip_tos_delay += 0; $ip_tos_precedence += 0; $ip_tos_reliability += 0; $ip_tos_throughput += 0;
    
    $tcp_flag_ack += 0; $tcp_flag_cwr += 0; $tcp_flag_ecn += 0; $tcp_flag_fin += 0; $tcp_flag_ns += 0; $tcp_flag_push += 0; $tcp_flag_res += 0; $tcp_flag_reset += 0; $tcp_flag_syn += 0; $tcp_flag_urg += 0;
    $tcp_len += 0; $tcp_opt_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0; $tcp_bytes_in_flight += 0; $tcp_win_size_scalefactor += 0; $tcp_win_size += 0; $tcp_pdu_size += 0; $tcp_reused_ports += 0;


    my @ip_srcs = split(/,/, $ip_src_list);
    my @ip_dsts = split(/,/, $ip_dst_list);

    foreach my $ip_src (@ip_srcs) {
        foreach my $ip_dst (@ip_dsts) {
            next unless($ip_src =~ /$ip/ or $ip_dst =~ /$ip/);

            # print "  $ip_src => $ip_dst: $ip_id\n";


            ###############
            ## port
            ##   %port_info
            ##   PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
            ###############
            # if($udp_sport != 0) {
            #     ## UDP
            #     if($ip_src =~ /$ip/) {
            #         ## sender
            #         print "  - UDP tx at $time: port=$udp_sport\n" if($DEBUG4);


            #         ## OS
            #         my $this_os;
            #         if(exists $os_info{$ip_src}) {
            #             $this_os = $os_info{$ip_src};
            #         }
            #         else {
            #             $this_os = "unknown";
            #         }

                    
            #         $port_info{PORT}{UDP}{TX}{TIME}{$time}{PORT} = $udp_sport;
            #         $port_info{PORT}{UDP}{TX}{TIME}{$time}{LEN} = $frame_len;

            #         $port_info{PORT}{UDP}{ALL}{TIME}{$time}{PORT} = $udp_sport;
            #         $port_info{PORT}{UDP}{ALL}{TIME}{$time}{LEN} = $frame_len;
            #     }
            #     elsif($ip_dst =~ /$ip/) {
            #         ## receiver
            #         print "  - UDP rx at $time: port=$udp_dport\n" if($DEBUG4);

            #         $port_info{PORT}{UDP}{RX}{TIME}{$time}{PORT} = $udp_dport;
            #         $port_info{PORT}{UDP}{RX}{TIME}{$time}{LEN} = $frame_len;

            #         $port_info{PORT}{UDP}{ALL}{TIME}{$time}{PORT} = $udp_dport;
            #         $port_info{PORT}{UDP}{ALL}{TIME}{$time}{LEN} = $frame_len;
            #     }
            #     else {
            #         die "neither sender nor receiver\n";
            #     }
            # }
            # elsif($tcp_sport != 0) {
            #     ## TCP
            #     if($ip_src =~ /$ip/) {
            #         ## sender
            #         print "  - TCP tx at $time: port=$tcp_sport\n" if($DEBUG4);

            #         $port_info{PORT}{TCP}{TX}{TIME}{$time}{PORT} = $tcp_sport;
            #         $port_info{PORT}{TCP}{TX}{TIME}{$time}{LEN} = $frame_len;

            #         $port_info{PORT}{TCP}{ALL}{TIME}{$time}{PORT} = $tcp_sport;
            #         $port_info{PORT}{TCP}{ALL}{TIME}{$time}{LEN} = $frame_len;
            #     }
            #     elsif($ip_dst =~ /$ip/) {
            #         ## receiver
            #         print "  - TCP rx at $time: port=$tcp_dport\n" if($DEBUG4);

            #         $port_info{PORT}{TCP}{RX}{TIME}{$time}{PORT} = $tcp_dport;
            #         $port_info{PORT}{TCP}{RX}{TIME}{$time}{LEN} = $frame_len;

            #         $port_info{PORT}{TCP}{ALL}{TIME}{$time}{PORT} = $tcp_dport;
            #         $port_info{PORT}{TCP}{ALL}{TIME}{$time}{LEN} = $frame_len;
            #     }
            #     else {
            #         die "neither sender nor receiver\n";
            #     }
            # }


            ###############
            ## IP info
            ##   my %ip_info
            ##   [TX | RX | ALL] - [CNT | DF | RB | SF]
            ##   [TX | RX | ALL] - [OPT_LEN | OPT_NUM | DS_CE | DS_DSCP | DS_ECN | DS_ECT | TOS_COST | TOS_DELAY | TOS_PRECEDENCE | TOS_RELIABILITY | TOS_TPUT] 
            ##         - value - count
            ###############
            my $this_txrx;
            my $this_os;
            if($ip_src =~ /$ip/) {
                ## sender
                $this_txrx = "TX";

                ## OS
                if(exists $os_info{$ip_src}) {
                    $this_os = $os_info{$ip_src};
                }
                else {
                    $this_os = "unknown";
                }

            }
            elsif($ip_dst =~ /$ip/) {
                ## receiver
                $this_txrx = "RX";

                ## OS
                if(exists $os_info{$ip_dst}) {
                    $this_os = $os_info{$ip_dst};
                }
                else {
                    $this_os = "unknown";
                }

            }
            else {
                die "neither sender nor receiver\n";
            }


            $ip_info{OS}{$this_os}{$this_txrx}{CNT} ++;
            $ip_info{OS}{$this_os}{ALL}{CNT} ++;


            ## flags
            print join("|||", ($ip_flag_df, $ip_flag_rb, $ip_flag_sf))."\n" if($DEBUG6);

            if($ip_flag_df == 1) {
                $ip_info{OS}{$this_os}{$this_txrx}{DF} ++;
                $ip_info{OS}{$this_os}{ALL}{DF} ++;
            }
            if($ip_flag_rb == 1) {
                $ip_info{OS}{$this_os}{$this_txrx}{RB} ++;
                $ip_info{OS}{$this_os}{ALL}{RB} ++;
            }
            if($ip_flag_sf == 1) {
                $ip_info{OS}{$this_os}{$this_txrx}{SF} ++;
                $ip_info{OS}{$this_os}{ALL}{SF} ++;
            }


            ## options
            print join("|||", ($ip_opt_len, $ip_opt_type_number))."\n" if($DEBUG6);

            $ip_info{OS}{$this_os}{$this_txrx}{OPT_LEN}{$ip_opt_len} ++;
            $ip_info{OS}{$this_os}{ALL}{OPT_LEN}{$ip_opt_len} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{OPT_NUM}{$ip_opt_type_number} ++;
            $ip_info{OS}{$this_os}{ALL}{OPT_NUM}{$ip_opt_type_number} ++;


            ## ds
            print join("|||", ($ip_dsfield_ce, $ip_dsfield_dscp, $ip_dsfield_ecn, $ip_dsfield_ect))."\n" if($DEBUG6);

            $ip_info{OS}{$this_os}{$this_txrx}{DS_CE}{$ip_dsfield_ce} ++;
            $ip_info{OS}{$this_os}{ALL}{DS_CE}{$ip_dsfield_ce} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{DS_DSCP}{$ip_dsfield_dscp} ++;
            $ip_info{OS}{$this_os}{ALL}{DS_DSCP}{$ip_dsfield_dscp} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{DS_ECN}{$ip_dsfield_ecn} ++;
            $ip_info{OS}{$this_os}{ALL}{DS_ECN}{$ip_dsfield_ecn} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{DS_ECT}{$ip_dsfield_ect} ++;
            $ip_info{OS}{$this_os}{ALL}{DS_ECT}{$ip_dsfield_ect} ++;


            ## TOS
            $ip_info{OS}{$this_os}{$this_txrx}{TOS_COST}{$ip_tos_cost} ++;
            $ip_info{OS}{$this_os}{ALL}{TOS_COST}{$ip_tos_cost} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{TOS_DELAY}{$ip_tos_delay} ++;
            $ip_info{OS}{$this_os}{ALL}{TOS_DELAY}{$ip_tos_delay} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{TOS_PRECEDENCE}{$ip_tos_precedence} ++;
            $ip_info{OS}{$this_os}{ALL}{TOS_PRECEDENCE}{$ip_tos_precedence} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{TOS_RELIABILITY}{$ip_tos_reliability} ++;
            $ip_info{OS}{$this_os}{ALL}{TOS_RELIABILITY}{$ip_tos_reliability} ++;

            $ip_info{OS}{$this_os}{$this_txrx}{TOS_TPUT}{$ip_tos_throughput} ++;
            $ip_info{OS}{$this_os}{ALL}{TOS_TPUT}{$ip_tos_throughput} ++;

            ## end IP


            ###############
            ## TCP info
            ##   my %tcp_info
            ##   [TX | RX | ALL] - [CNT | ACK | CWR | ECN | FIN | NS | PUSH | RES | RESET | SYN | URG]
            ##   [TX | RX | ALL] - [LEN | OPT_KIND | OPT_LEN | FLIGHT | WIN_SCALE | WIN_SIZE | PDU_SIZE | CONT | REUSED_PORT] 
            ##         - value - count
            ###############
            if($tcp_sport != 0) {

                $tcp_info{OS}{$this_os}{$this_txrx}{CNT} ++;
                $tcp_info{OS}{$this_os}{ALL}{CNT} ++;


                ## flags
                print join("|||", ($tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg))."\n" if($DEBUG5);

                if($tcp_flag_ack == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{ACK} ++;
                    $tcp_info{OS}{$this_os}{ALL}{ACK} ++;
                }
                if($tcp_flag_cwr == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{CWR} ++;
                    $tcp_info{OS}{$this_os}{ALL}{CWR} ++;
                }
                if($tcp_flag_ecn == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{ECN} ++;
                    $tcp_info{OS}{$this_os}{ALL}{ECN} ++;
                }
                if($tcp_flag_fin == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{FIN} ++;
                    $tcp_info{OS}{$this_os}{ALL}{FIN} ++;
                }
                if($tcp_flag_ns == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{NS} ++;
                    $tcp_info{OS}{$this_os}{ALL}{NS} ++;
                }
                if($tcp_flag_push == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{PUSH} ++;
                    $tcp_info{OS}{$this_os}{ALL}{PUSH} ++;
                }
                if($tcp_flag_res == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{RES} ++;
                    $tcp_info{OS}{$this_os}{ALL}{RES} ++;
                }
                if($tcp_flag_reset == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{RESET} ++;
                    $tcp_info{OS}{$this_os}{ALL}{RESET} ++;
                }
                if($tcp_flag_syn == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{SYN} ++;
                    $tcp_info{OS}{$this_os}{ALL}{SYN} ++;
                }
                if($tcp_flag_urg == 1) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{URG} ++;
                    $tcp_info{OS}{$this_os}{ALL}{URG} ++;
                }


                $tcp_info{OS}{$this_os}{$this_txrx}{LEN}{$tcp_len} ++;
                $tcp_info{OS}{$this_os}{$this_txrx}{LEN_SUM} += $tcp_len;
                $tcp_info{OS}{$this_os}{ALL}{LEN}{$tcp_len} ++;
                $tcp_info{OS}{$this_os}{ALL}{LEN_SUM} += $tcp_len;

                if($tcp_opt_kind ne "") {
                    my @kinds = split(/,/, $tcp_opt_kind);
                    foreach my $kind (@kinds) {
                        $kind += 0;
                        $tcp_info{OS}{$this_os}{$this_txrx}{OPT_KIND}{$kind} ++;
                        $tcp_info{OS}{$this_os}{ALL}{OPT_KIND}{$kind} ++;
                    }
                    $tcp_info{OS}{$this_os}{$this_txrx}{NUM_OPT_KIND}{scalar(@kinds)} ++;
                    $tcp_info{OS}{$this_os}{ALL}{NUM_OPT_KIND}{scalar(@kinds)} ++;
                }
                else {
                    $tcp_info{OS}{$this_os}{$this_txrx}{NUM_OPT_KIND}{0} ++;
                    $tcp_info{OS}{$this_os}{ALL}{NUM_OPT_KIND}{0} ++;
                }

                $tcp_info{OS}{$this_os}{$this_txrx}{OPT_LEN}{$tcp_opt_len} ++;
                $tcp_info{OS}{$this_os}{$this_txrx}{OPT_LEN_SUM} += $tcp_opt_len;
                $tcp_info{OS}{$this_os}{ALL}{OPT_LEN}{$tcp_opt_len} ++;
                $tcp_info{OS}{$this_os}{ALL}{OPT_LEN_SUM} += $tcp_opt_len;

                $tcp_info{OS}{$this_os}{$this_txrx}{FLIGHT}{TIME}{$time}{FLIGHT} = $tcp_bytes_in_flight;
                $tcp_info{OS}{$this_os}{ALL}{FLIGHT}{TIME}{$time}{FLIGHT} = $tcp_bytes_in_flight;

                if($tcp_win_size_scalefactor >= 0) {
                    $tcp_info{OS}{$this_os}{$this_txrx}{WIN_SCALE}{$tcp_win_size_scalefactor} ++;
                    $tcp_info{OS}{$this_os}{ALL}{WIN_SCALE}{$tcp_win_size_scalefactor} ++;
                }

                $tcp_info{OS}{$this_os}{$this_txrx}{WIN_SIZE}{$tcp_win_size} ++;
                $tcp_info{OS}{$this_os}{ALL}{WIN_SIZE}{$tcp_win_size} ++;

                $tcp_info{OS}{$this_os}{$this_txrx}{PDU_SIZE}{$tcp_pdu_size} ++;
                $tcp_info{OS}{$this_os}{ALL}{PDU_SIZE}{$tcp_pdu_size} ++;

                $tcp_info{OS}{$this_os}{$this_txrx}{CONT}{$tcp_cont} ++;
                $tcp_info{OS}{$this_os}{ALL}{CONT}{$tcp_cont} ++;

                $tcp_info{OS}{$this_os}{$this_txrx}{REUSED_PORT}{$tcp_reused_ports} ++;
                $tcp_info{OS}{$this_os}{ALL}{REUSED_PORT}{$tcp_reused_ports} ++;

                print "$tcp_cont\n" if($DEBUG0 and $tcp_cont ne "");
                print "$tcp_reused_ports\n" if($DEBUG0 and $tcp_reused_ports != 0);
            }  ## end if TCP

        }
    }
}
close FH;


###############
## output port info
##   %port_info
##   PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
###############
# print "Output port info\n" if($DEBUG2);

# foreach my $protocol ("UDP", "TCP") {
#     foreach my $txrx ("TX", "RX", "ALL") {
#         open FH, "> $output_dir/$filename.$protocol.$txrx.txt" or die $!;
#         my $first_time = -1;
#         foreach my $time (sort {$a <=> $b} (keys %{ $port_info{PORT}{$protocol}{$txrx}{TIME} })) {
#             $first_time = $time if($first_time == -1);
#             print FH "".($time-$first_time).", ".$port_info{PORT}{$protocol}{$txrx}{TIME}{$time}{PORT}.", ".$port_info{PORT}{$protocol}{$txrx}{TIME}{$time}{LEN}."\n";
#         }
#         close FH;

        
#         print "  gnuplot\n" if($DEBUG2);
#         my $cmd = "sed 's/FILE_NAME/$filename.$protocol.$txrx/g; s/FIG_NAME/$filename.$protocol.$txrx/g; s/X_LABEL/time/g; s/Y_LABEL/port/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_port.mother.plot > tmp.$gnuplot_port.$protocol.$txrx.plot";
#         `$cmd`;

#         $cmd = "gnuplot tmp.$gnuplot_port.$protocol.$txrx.plot";
#         `$cmd`;
#     }
# }



###############
## output flag and other info
##   my %tcp_info
##   [TX | RX | ALL] - [CNT | ACK | CWR | ECN | FIN | NS | PUSH | RES | RESET | SYN | URG]
##   [TX | RX | ALL] - [LEN | OPT_KIND | OPT_LEN | FLIGHT | WIN_SCALE | WIN_SIZE | PDU_SIZE | CONT | REUSED_PORT] 
##         - value - count
###############
print "Output TCP flag info\n" if($DEBUG2);
foreach my $this_os (keys %{ $tcp_info{OS} }) {
    print "  $this_os:\n";
    print "    # tx TCP pkts = ".$tcp_info{OS}{$this_os}{TX}{CNT}."\n";
    print "    # rx TCP pkts = ".$tcp_info{OS}{$this_os}{RX}{CNT}."\n";
    print "    avg tx len = ".($tcp_info{OS}{$this_os}{TX}{LEN_SUM} / $tcp_info{OS}{$this_os}{TX}{CNT})."\n";
    print "    avg rx len = ".($tcp_info{OS}{$this_os}{RX}{LEN_SUM} / $tcp_info{OS}{$this_os}{RX}{CNT})."\n";
    print "    avg len = ".($tcp_info{OS}{$this_os}{ALL}{LEN_SUM} / $tcp_info{OS}{$this_os}{ALL}{CNT})."\n";
    print "    avg tx opt len = ".($tcp_info{OS}{$this_os}{TX}{OPT_LEN_SUM} / $tcp_info{OS}{$this_os}{TX}{CNT})."\n";
    print "    avg rx opt len = ".($tcp_info{OS}{$this_os}{RX}{OPT_LEN_SUM} / $tcp_info{OS}{$this_os}{RX}{CNT})."\n";
    print "    avg opt len = ".($tcp_info{OS}{$this_os}{ALL}{OPT_LEN_SUM} / $tcp_info{OS}{$this_os}{ALL}{CNT})."\n";
    print "\n";

    foreach my $txrx ("TX", "RX", "ALL") {
        ###############
        ## flags
        ###############
        my $out_file_suffix = "$this_os.tcp_flags.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $flag ("ACK", "FIN", "SYN", "CWR", "ECN", "NS", "PUSH", "RES", "RESET", "URG") {
            $tcp_info{OS}{$this_os}{$txrx}{$flag} = 0 unless(exists $tcp_info{OS}{$this_os}{$txrx}{$flag});
            print FH "$flag, ".($tcp_info{OS}{$this_os}{$txrx}{$flag} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$flag}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E/0.1/g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## TCP length
        ###############
        $out_file_suffix = "$this_os.pkt_len.$txrx";
        my $factor = "LEN";
        ## find top n    
        my @top_n_keys = ();
        foreach my $this_len (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            $tcp_info{OS}{$this_os}{$txrx}{$factor} = 0 unless(exists $tcp_info{OS}{$this_os}{$txrx}{$factor});
            
            if(scalar(@top_n_keys) < $TOP_N) {
                push(@top_n_keys, $this_len);
            }
            else {
                foreach my $ind (0 .. $TOP_N-1) {
                    my $this_key = $top_n_keys[$ind];
                    
                    if($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_len} > $tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_key}) {
                        $top_n_keys[$ind] = $this_len;
                        last;
                    }
                }
            }
        }
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_len (sort {$a <=> $b} @top_n_keys) {
            print FH "$this_len, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_len} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_len}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## TCP Option kinds
        ###############
        $out_file_suffix = "$this_os.tcp_opt_kinds.$txrx";
        $factor = "OPT_KIND";
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_kind (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            print FH "$this_kind, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_kind} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_kind}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## Number of TCP Option kinds
        ###############
        $out_file_suffix = "$this_os.tcp_opt_kinds_num.$txrx";
        $factor = "NUM_OPT_KIND";
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_num (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            print FH "$this_num, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_num} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_num}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## TCP option length
        ###############
        $out_file_suffix = "$this_os.opt_len.$txrx";
        $factor = "OPT_LEN";
        ## find top n    
        @top_n_keys = ();
        foreach my $this_len (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            $tcp_info{OS}{$this_os}{$txrx}{$factor} = 0 unless(exists $tcp_info{OS}{$this_os}{$txrx}{$factor});
            
            if(scalar(@top_n_keys) < $TOP_N) {
                push(@top_n_keys, $this_len);
            }
            else {
                foreach my $ind (0 .. $TOP_N-1) {
                    my $this_key = $top_n_keys[$ind];
                    
                    if($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_len} > $tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_key}) {
                        $top_n_keys[$ind] = $this_len;
                        last;
                    }
                }
            }
        }
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_len (sort {$a <=> $b} @top_n_keys) {
            print FH "$this_len, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_len} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_len}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## Bytes in flight
        ###############
        $out_file_suffix = "$this_os.tcp_bytes_in_flight.$txrx";
        $factor = "FLIGHT";

        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        my $first_time = -1;
        foreach my $time (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor}{TIME} })) {
            $first_time = $time if($first_time == -1);
            print FH "".($time-$first_time).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{TIME}{$time}{FLIGHT}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL/time/g; s/Y_LABEL/bytes in flight/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_port.mother.plot > tmp.$gnuplot_port.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_port.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## TCP win size scalefactor
        ###############
        $out_file_suffix = "$this_os.win_scale.$txrx";
        $factor = "WIN_SCALE";
        ## find top n    
        my @top_n_keys = ();
        foreach my $this_scale (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            $tcp_info{OS}{$this_os}{$txrx}{$factor} = 0 unless(exists $tcp_info{OS}{$this_os}{$txrx}{$factor});
            
            if(scalar(@top_n_keys) < $TOP_N) {
                push(@top_n_keys, $this_scale);
            }
            else {
                foreach my $ind (0 .. $TOP_N-1) {
                    my $this_key = $top_n_keys[$ind];
                    
                    if($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_scale} > $tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_key}) {
                        $top_n_keys[$ind] = $this_scale;
                        last;
                    }
                }
            }
        }
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_scale (sort {$a <=> $b} @top_n_keys) {
            print FH "$this_scale, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_scale} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_scale}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## TCP win size
        ###############
        $out_file_suffix = "$this_os.win_size.$txrx";
        $factor = "WIN_SIZE";
        ## find top n    
        my @top_n_keys = ();
        foreach my $this_size (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            $tcp_info{OS}{$this_os}{$txrx}{$factor} = 0 unless(exists $tcp_info{OS}{$this_os}{$txrx}{$factor});
            
            if(scalar(@top_n_keys) < $TOP_N) {
                push(@top_n_keys, $this_size);
            }
            else {
                foreach my $ind (0 .. $TOP_N-1) {
                    my $this_key = $top_n_keys[$ind];
                    
                    if($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_size} > $tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_key}) {
                        $top_n_keys[$ind] = $this_size;
                        last;
                    }
                }
            }
        }
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_size (sort {$a <=> $b} @top_n_keys) {
            print FH "$this_size, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_size} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_size}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## PDU size
        ###############
        $out_file_suffix = "$this_os.pdu_size.$txrx";
        $factor = "PDU_SIZE";
        ## find top n    
        my @top_n_keys = ();
        foreach my $this_size (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            $tcp_info{OS}{$this_os}{$txrx}{$factor} = 0 unless(exists $tcp_info{OS}{$this_os}{$txrx}{$factor});
            
            if(scalar(@top_n_keys) < $TOP_N) {
                push(@top_n_keys, $this_size);
            }
            else {
                foreach my $ind (0 .. $TOP_N-1) {
                    my $this_key = $top_n_keys[$ind];
                    
                    if($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_size} > $tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_key}) {
                        $top_n_keys[$ind] = $this_size;
                        last;
                    }
                }
            }
        }
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_size (sort {$a <=> $b} @top_n_keys) {
            print FH "$this_size, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_size} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_size}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## reused ports
        ###############
        $out_file_suffix = "$this_os.reused_ports.$txrx";
        $factor = "REUSED_PORT";
        ## find top n    
        my @top_n_keys = ();
        foreach my $this_p (sort {$a <=> $b} (keys %{ $tcp_info{OS}{$this_os}{$txrx}{$factor} })) {
            $tcp_info{OS}{$this_os}{$txrx}{$factor} = 0 unless(exists $tcp_info{OS}{$this_os}{$txrx}{$factor});
            
            if(scalar(@top_n_keys) < $TOP_N) {
                push(@top_n_keys, $this_p);
            }
            else {
                foreach my $ind (0 .. $TOP_N-1) {
                    my $this_key = $top_n_keys[$ind];
                    
                    if($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_p} > $tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_key}) {
                        $top_n_keys[$ind] = $this_p;
                        last;
                    }
                }
            }
        }
        
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $this_p (sort {$a <=> $b} @top_n_keys) {
            print FH "$this_p, ".($tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_p} / $tcp_info{OS}{$this_os}{$txrx}{CNT}).", ".$tcp_info{OS}{$this_os}{$txrx}{$factor}{$this_p}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;
    }
}







###############
## output IP flag and other info 
##   my %ip_info
##   [TX | RX | ALL] - [CNT | DF | RB | SF]
##   [TX | RX | ALL] - [OPT_LEN | OPT_NUM | DS_CE | DS_DSCP | DS_ECN | DS_ECT | TOS_COST | TOS_DELAY | TOS_PRECEDENCE | TOS_RELIABILITY | TOS_TPUT] 
##         - value - count
###############
print "Output IP flag info\n" if($DEBUG2);

foreach my $this_os (keys %{ $ip_info{OS} }) {
    print "  $this_os\n";
    print "    # tx IP pkts = ".$ip_info{OS}{$this_os}{TX}{CNT}."\n";
    print "    # rx IP pkts = ".$ip_info{OS}{$this_os}{RX}{CNT}."\n";
    print "\n";

    foreach my $txrx ("TX", "RX", "ALL") {
        ###############
        ## flags
        ###############
        my $out_file_suffix = "$this_os.ip_flags.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $flag ("DF", "RB", "SF") {
            $ip_info{OS}{$this_os}{$txrx}{$flag} = 0 unless(exists $ip_info{OS}{$this_os}{$txrx}{$flag});
            print FH "$flag, ".($ip_info{OS}{$this_os}{$txrx}{$flag} / $ip_info{OS}{$this_os}{$txrx}{CNT}).", ".$ip_info{OS}{$this_os}{$txrx}{$flag}."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## options
        ###############
        my $out_file_suffix = "$this_os.ip_option.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $opt_len (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{OPT_LEN} })) {
            print FH "$opt_len, ".($ip_info{OS}{$this_os}{$txrx}{OPT_LEN}{$opt_len} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_option_num.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $opt_num (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{OPT_NUM} })) {
            print FH "$opt_num, ".($ip_info{OS}{$this_os}{$txrx}{OPT_NUM}{$opt_num} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## dsfield: DS_CE | DS_DSCP | DS_ECN | DS_ECT
        ###############
        my $out_file_suffix = "$this_os.ip_ds_ce.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ds_ce (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{DS_CE} })) {
            print FH "$ds_ce, ".($ip_info{OS}{$this_os}{$txrx}{DS_CE}{$ds_ce} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_ds_dscp.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ds_dscp (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{DS_DSCP} })) {
            print FH "$ds_dscp, ".($ip_info{OS}{$this_os}{$txrx}{DS_DSCP}{$ds_dscp} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_ds_ecn.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ds_ecn (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{DS_ECN} })) {
            print FH "$ds_ecn, ".($ip_info{OS}{$this_os}{$txrx}{DS_ECN}{$ds_ecn} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_ds_ect.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ds_ect (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{DS_ECT} })) {
            print FH "$ds_ect, ".($ip_info{OS}{$this_os}{$txrx}{DS_ECT}{$ds_ect} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        ###############
        ## dsfield: TOS_COST | TOS_DELAY | TOS_PRECEDENCE | TOS_RELIABILITY | TOS_TPUT
        ###############
        my $out_file_suffix = "$this_os.ip_tos_cost.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ip_tos_cost (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{TOS_COST} })) {
            print FH "$ip_tos_cost, ".($ip_info{OS}{$this_os}{$txrx}{TOS_COST}{$ip_tos_cost} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_tos_delay.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ip_tos_delay (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{TOS_DELAY} })) {
            print FH "$ip_tos_delay, ".($ip_info{OS}{$this_os}{$txrx}{TOS_DELAY}{$ip_tos_delay} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_tos_precedence.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ip_tos_precedence (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{TOS_PRECEDENCE} })) {
            print FH "$ip_tos_precedence, ".($ip_info{OS}{$this_os}{$txrx}{TOS_PRECEDENCE}{$ip_tos_precedence} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_tos_reliability.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ip_tos_reliability (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{TOS_RELIABILITY} })) {
            print FH "$ip_tos_reliability, ".($ip_info{OS}{$this_os}{$txrx}{TOS_RELIABILITY}{$ip_tos_reliability} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;


        my $out_file_suffix = "$this_os.ip_tos_throughput.$txrx";
        open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
        foreach my $ip_tos_throughput (sort {$a <=> $b} (keys %{ $ip_info{OS}{$this_os}{$txrx}{TOS_TPUT} })) {
            print FH "$ip_tos_throughput, ".($ip_info{OS}{$this_os}{$txrx}{TOS_TPUT}{$ip_tos_throughput} / $ip_info{OS}{$this_os}{$txrx}{CNT})."\n";
        }
        close FH;

        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
        `$cmd`;

    }
}


my $cmd = "rm tmp*";
`$cmd`;

