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
##   perl analyze_port.pl 192.168.0.2 2013.10.30.windows.youtube.pcap.txt 
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

my %port_info = ();  ## PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
my %ip_info   = ();  ## [CNT | DF | RB | SF]
                     ## [OPT_LEN | OPT_NUM | DS_CE | DS_DSCP | DS_ECN | DS_ECT] 
my %tcp_info  = ();  ## [CNT | ACK | CWR | ECN | FIN | NS | PUSH | RES | RESET | SYN | URG]
                     ## [LEN | OPT_KIND | OPT_LEN | FLIGHT | WIN_SCALE | WIN_SIZE | PDU_SIZE | CONT | REUSED_PORT] - value - count



#############
# check input
#############
if(@ARGV != 2) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$ip = $ARGV[0];
$filename = $ARGV[1];
if($DEBUG2) {
    print "ip: $ip\n";
    print "file: $filename\n";
}


#############
# Main starts
#############
print "start to read trace file\n" if($DEBUG2);

open FH, "$input_dir/$filename" or die $!;
while(<FH>) {
    chomp;
    print "> $_\n" if($DEBUG4);

    # my ($frame_num, $time, $frame_len, $ip_id, $ip_src, $ip_dst, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports) = split(/\|/, $_);
    
    # my ($frame_num, $time, $frame_len, $ip_id, $ip_src, $ip_dst, $ip_flag_df, $ip_flag_rb, $ip_flag_sf, $ip_opt_len, $ip_opt_type_number, $ip_opt_ext_sec_add_sec_info, $ip_opt_id_number, $ip_opt_mtu, $ip_opt_ohc, $ip_opt_padding, $ip_opt_ptr, $ip_opt_qs_rate, $ip_opt_qs_ttl, $ip_opt_qs_unused, $ip_opt_sec_cl, $ip_opt_sid, $ip_dsfield_ce, $ip_dsfield_dscp, $ip_dsfield_ecn, $ip_dsfield_ect, $ip_tos_cost, $ip_tos_delay, $ip_tos_precedence, $ip_tos_reliability, $ip_tos_throughput, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports) = split(/\|/, $_);
    
    my ($frame_num, $time, $frame_len, $ip_src, $ip_dst, $ip_id, $ip_ttl, $ip_flag_df, $ip_flag_rb, $ip_flag_sf, $ip_opt_len, $ip_opt_type_number, $ip_opt_ext_sec_add_sec_info, $ip_opt_id_number, $ip_opt_mtu, $ip_opt_ohc, $ip_opt_padding, $ip_opt_ptr, $ip_opt_qs_rate, $ip_opt_qs_ttl, $ip_opt_qs_unused, $ip_opt_sec_cl, $ip_opt_sid, $ip_dsfield_ce, $ip_dsfield_dscp, $ip_dsfield_ecn, $ip_dsfield_ect, $ip_tos_cost, $ip_tos_delay, $ip_tos_precedence, $ip_tos_reliability, $ip_tos_throughput, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_seq, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_ts_val, $tcp_ts_ecr, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports, $ua) = split(/\|/, $_);
    $time += 0; $frame_len += 0; $udp_sport += 0; $udp_dport += 0; $tcp_sport += 0; $tcp_dport += 0;
    $ip_id = hex($ip_id);
    $ip_flag_df += 0; $ip_flag_rb += 0; $ip_flag_sf += 0; 
    $ip_opt_len += 0; $ip_opt_type_number += 0; $ip_opt_ext_sec_add_sec_info += 0; $ip_opt_id_number += 0; $ip_opt_mtu += 0; $ip_opt_ohc += 0; $ip_opt_padding += 0; $ip_opt_ptr += 0; $ip_opt_qs_rate += 0; $ip_opt_qs_ttl += 0; $ip_opt_qs_unused += 0; $ip_opt_sec_cl += 0; $ip_opt_sid += 0; 
    $ip_dsfield_ce += 0; $ip_dsfield_dscp += 0; $ip_dsfield_ecn += 0; $ip_dsfield_ect += 0;
    $ip_tos_cost += 0; $ip_tos_delay += 0; $ip_tos_precedence += 0; $ip_tos_reliability += 0; $ip_tos_throughput += 0;
    $tcp_flag_ack += 0; $tcp_flag_cwr += 0; $tcp_flag_ecn += 0; $tcp_flag_fin += 0; $tcp_flag_ns += 0; $tcp_flag_push += 0; $tcp_flag_res += 0; $tcp_flag_reset += 0; $tcp_flag_syn += 0; $tcp_flag_urg += 0;
    $tcp_len += 0; $tcp_opt_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0; $tcp_bytes_in_flight += 0; $tcp_win_size_scalefactor += 0; $tcp_win_size += 0; $tcp_pdu_size += 0; $tcp_reused_ports += 0;


    ###############
    ## port
    ##   %port_info
    ##   PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
    ###############
    if($udp_sport != 0) {
        ## UDP
        if($ip_src =~ /$ip/) {
            ## sender
            print "  - UDP tx at $time: port=$udp_sport\n" if($DEBUG4);

            $port_info{PORT}{UDP}{TX}{TIME}{$time}{PORT} = $udp_sport;
            $port_info{PORT}{UDP}{TX}{TIME}{$time}{LEN} = $frame_len;

            $port_info{PORT}{UDP}{ALL}{TIME}{$time}{PORT} = $udp_sport;
            $port_info{PORT}{UDP}{ALL}{TIME}{$time}{LEN} = $frame_len;
        }
        elsif($ip_dst =~ /$ip/) {
            ## receiver
            print "  - UDP rx at $time: port=$udp_dport\n" if($DEBUG4);

            $port_info{PORT}{UDP}{RX}{TIME}{$time}{PORT} = $udp_dport;
            $port_info{PORT}{UDP}{RX}{TIME}{$time}{LEN} = $frame_len;

            $port_info{PORT}{UDP}{ALL}{TIME}{$time}{PORT} = $udp_dport;
            $port_info{PORT}{UDP}{ALL}{TIME}{$time}{LEN} = $frame_len;
        }
        else {
            die "neither sender nor receiver\n";
        }
    }
    elsif($tcp_sport != 0) {
        ## TCP
        if($ip_src =~ /$ip/) {
            ## sender
            print "  - TCP tx at $time: port=$tcp_sport\n" if($DEBUG4);

            $port_info{PORT}{TCP}{TX}{TIME}{$time}{PORT} = $tcp_sport;
            $port_info{PORT}{TCP}{TX}{TIME}{$time}{LEN} = $frame_len;

            $port_info{PORT}{TCP}{ALL}{TIME}{$time}{PORT} = $tcp_sport;
            $port_info{PORT}{TCP}{ALL}{TIME}{$time}{LEN} = $frame_len;
        }
        elsif($ip_dst =~ /$ip/) {
            ## receiver
            print "  - TCP rx at $time: port=$tcp_dport\n" if($DEBUG4);

            $port_info{PORT}{TCP}{RX}{TIME}{$time}{PORT} = $tcp_dport;
            $port_info{PORT}{TCP}{RX}{TIME}{$time}{LEN} = $frame_len;

            $port_info{PORT}{TCP}{ALL}{TIME}{$time}{PORT} = $tcp_dport;
            $port_info{PORT}{TCP}{ALL}{TIME}{$time}{LEN} = $frame_len;
        }
        else {
            die "neither sender nor receiver\n";
        }
    }


    ###############
    ## IP info
    ##   my %ip_info
    ##   [TX | RX | ALL] - [CNT | DF | RB | SF]
    ##   [TX | RX | ALL] - [OPT_LEN | OPT_NUM | DS_CE | DS_DSCP | DS_ECN | DS_ECT | TOS_COST | TOS_DELAY | TOS_PRECEDENCE | TOS_RELIABILITY | TOS_TPUT] 
    ##         - value - count
    ###############
    if($ip_src =~ /$ip/) {
        ## sender
        $ip_info{TX}{CNT} ++;
        $ip_info{ALL}{CNT} ++;

        ## flags
        print join("|||", ($ip_flag_df, $ip_flag_rb, $ip_flag_sf))."\n" if($DEBUG6);

        if($ip_flag_df == 1) {
            $ip_info{TX}{DF} ++;
            $ip_info{ALL}{DF} ++;
        }
        if($ip_flag_rb == 1) {
            $ip_info{TX}{RB} ++;
            $ip_info{ALL}{RB} ++;
        }
        if($ip_flag_sf == 1) {
            $ip_info{TX}{SF} ++;
            $ip_info{ALL}{SF} ++;
        }


        ## options
        print join("|||", ($ip_opt_len, $ip_opt_type_number))."\n" if($DEBUG6);

        $ip_info{TX}{OPT_LEN}{$ip_opt_len} ++;
        $ip_info{ALL}{OPT_LEN}{$ip_opt_len} ++;

        $ip_info{TX}{OPT_NUM}{$ip_opt_type_number} ++;
        $ip_info{ALL}{OPT_NUM}{$ip_opt_type_number} ++;


        ## ds
        print join("|||", ($ip_dsfield_ce, $ip_dsfield_dscp, $ip_dsfield_ecn, $ip_dsfield_ect))."\n" if($DEBUG6);

        $ip_info{TX}{DS_CE}{$ip_dsfield_ce} ++;
        $ip_info{ALL}{DS_CE}{$ip_dsfield_ce} ++;

        $ip_info{TX}{DS_DSCP}{$ip_dsfield_dscp} ++;
        $ip_info{ALL}{DS_DSCP}{$ip_dsfield_dscp} ++;

        $ip_info{TX}{DS_ECN}{$ip_dsfield_ecn} ++;
        $ip_info{ALL}{DS_ECN}{$ip_dsfield_ecn} ++;

        $ip_info{TX}{DS_ECT}{$ip_dsfield_ect} ++;
        $ip_info{ALL}{DS_ECT}{$ip_dsfield_ect} ++;


        ## TOS
        $ip_info{TX}{TOS_COST}{$ip_tos_cost} ++;
        $ip_info{ALL}{TOS_COST}{$ip_tos_cost} ++;

        $ip_info{TX}{TOS_DELAY}{$ip_tos_delay} ++;
        $ip_info{ALL}{TOS_DELAY}{$ip_tos_delay} ++;

        $ip_info{TX}{TOS_PRECEDENCE}{$ip_tos_precedence} ++;
        $ip_info{ALL}{TOS_PRECEDENCE}{$ip_tos_precedence} ++;

        $ip_info{TX}{TOS_RELIABILITY}{$ip_tos_reliability} ++;
        $ip_info{ALL}{TOS_RELIABILITY}{$ip_tos_reliability} ++;

        $ip_info{TX}{TOS_TPUT}{$ip_tos_throughput} ++;
        $ip_info{ALL}{TOS_TPUT}{$ip_tos_throughput} ++;

    }
    elsif($ip_dst =~ /$ip/) {
        ## receiver
        $ip_info{RX}{CNT} ++;
        $ip_info{ALL}{CNT} ++;

        ## flags
        print join("|||", ($ip_flag_df, $ip_flag_rb, $ip_flag_sf))."\n" if($DEBUG6);

        if($ip_flag_df == 1) {
            $ip_info{RX}{DF} ++;
            $ip_info{ALL}{DF} ++;
        }
        if($ip_flag_rb == 1) {
            $ip_info{RX}{RB} ++;
            $ip_info{ALL}{RB} ++;
        }
        if($ip_flag_sf == 1) {
            $ip_info{RX}{SF} ++;
            $ip_info{ALL}{SF} ++;
        }

        ## options
        print join("|||", ($ip_opt_len, $ip_opt_type_number))."\n" if($DEBUG6);

        $ip_info{RX}{OPT_LEN}{$ip_opt_len} ++;
        $ip_info{ALL}{OPT_LEN}{$ip_opt_len} ++;

        $ip_info{RX}{OPT_NUM}{$ip_opt_type_number} ++;
        $ip_info{ALL}{OPT_NUM}{$ip_opt_type_number} ++;


        ## ds
        print join("|||", ($ip_dsfield_ce, $ip_dsfield_dscp, $ip_dsfield_ecn, $ip_dsfield_ect))."\n" if($DEBUG6);

        $ip_info{RX}{DS_CE}{$ip_dsfield_ce} ++;
        $ip_info{ALL}{DS_CE}{$ip_dsfield_ce} ++;

        $ip_info{RX}{DS_DSCP}{$ip_dsfield_dscp} ++;
        $ip_info{ALL}{DS_DSCP}{$ip_dsfield_dscp} ++;

        $ip_info{RX}{DS_ECN}{$ip_dsfield_ecn} ++;
        $ip_info{ALL}{DS_ECN}{$ip_dsfield_ecn} ++;

        $ip_info{RX}{DS_ECT}{$ip_dsfield_ect} ++;
        $ip_info{ALL}{DS_ECT}{$ip_dsfield_ect} ++;


        ## TOS
        $ip_info{RX}{TOS_COST}{$ip_tos_cost} ++;
        $ip_info{ALL}{TOS_COST}{$ip_tos_cost} ++;

        $ip_info{RX}{TOS_DELAY}{$ip_tos_delay} ++;
        $ip_info{ALL}{TOS_DELAY}{$ip_tos_delay} ++;

        $ip_info{RX}{TOS_PRECEDENCE}{$ip_tos_precedence} ++;
        $ip_info{ALL}{TOS_PRECEDENCE}{$ip_tos_precedence} ++;

        $ip_info{RX}{TOS_RELIABILITY}{$ip_tos_reliability} ++;
        $ip_info{ALL}{TOS_RELIABILITY}{$ip_tos_reliability} ++;

        $ip_info{RX}{TOS_TPUT}{$ip_tos_throughput} ++;
        $ip_info{ALL}{TOS_TPUT}{$ip_tos_throughput} ++;
    }



    ###############
    ## TCP info
    ##   my %tcp_info
    ##   [TX | RX | ALL] - [CNT | ACK | CWR | ECN | FIN | NS | PUSH | RES | RESET | SYN | URG]
    ##   [TX | RX | ALL] - [LEN | OPT_KIND | OPT_LEN | FLIGHT | WIN_SCALE | WIN_SIZE | PDU_SIZE | CONT | REUSED_PORT] 
    ##         - value - count
    ###############
    if($tcp_sport != 0) {

        if($ip_src =~ /$ip/) {
            ## sender
            $tcp_info{TX}{CNT} ++;
            $tcp_info{ALL}{CNT} ++;

            ## flags
            print join("|||", ($tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg))."\n" if($DEBUG5);

            if($tcp_flag_ack == 1) {
                $tcp_info{TX}{ACK} ++;
                $tcp_info{ALL}{ACK} ++;
            }
            if($tcp_flag_cwr == 1) {
                $tcp_info{TX}{CWR} ++;
                $tcp_info{ALL}{CWR} ++;
            }
            if($tcp_flag_ecn == 1) {
                $tcp_info{TX}{ECN} ++;
                $tcp_info{ALL}{ECN} ++;
            }
            if($tcp_flag_fin == 1) {
                $tcp_info{TX}{FIN} ++;
                $tcp_info{ALL}{FIN} ++;
            }
            if($tcp_flag_ns == 1) {
                $tcp_info{TX}{NS} ++;
                $tcp_info{ALL}{NS} ++;
            }
            if($tcp_flag_push == 1) {
                $tcp_info{TX}{PUSH} ++;
                $tcp_info{ALL}{PUSH} ++;
            }
            if($tcp_flag_res == 1) {
                $tcp_info{TX}{RES} ++;
                $tcp_info{ALL}{RES} ++;
            }
            if($tcp_flag_reset == 1) {
                $tcp_info{TX}{RESET} ++;
                $tcp_info{ALL}{RESET} ++;
            }
            if($tcp_flag_syn == 1) {
                $tcp_info{TX}{SYN} ++;
                $tcp_info{ALL}{SYN} ++;
            }
            if($tcp_flag_urg == 1) {
                $tcp_info{TX}{URG} ++;
                $tcp_info{ALL}{URG} ++;
            }


            $tcp_info{TX}{LEN}{$tcp_len} ++;
            $tcp_info{TX}{LEN_SUM} += $tcp_len;
            $tcp_info{ALL}{LEN}{$tcp_len} ++;
            $tcp_info{ALL}{LEN_SUM} += $tcp_len;

            if($tcp_opt_kind ne "") {
                my @kinds = split(/,/, $tcp_opt_kind);
                foreach my $kind (@kinds) {
                    $kind += 0;
                    $tcp_info{TX}{OPT_KIND}{$kind} ++;
                    $tcp_info{ALL}{OPT_KIND}{$kind} ++;
                }
                $tcp_info{TX}{NUM_OPT_KIND}{scalar(@kinds)} ++;
                $tcp_info{ALL}{NUM_OPT_KIND}{scalar(@kinds)} ++;
            }
            else {
                $tcp_info{TX}{NUM_OPT_KIND}{0} ++;
                $tcp_info{ALL}{NUM_OPT_KIND}{0} ++;
            }

            $tcp_info{TX}{OPT_LEN}{$tcp_opt_len} ++;
            $tcp_info{TX}{OPT_LEN_SUM} += $tcp_opt_len;
            $tcp_info{ALL}{OPT_LEN}{$tcp_opt_len} ++;
            $tcp_info{ALL}{OPT_LEN_SUM} += $tcp_opt_len;

            $tcp_info{TX}{FLIGHT}{TIME}{$time}{FLIGHT} = $tcp_bytes_in_flight;
            $tcp_info{ALL}{FLIGHT}{TIME}{$time}{FLIGHT} = $tcp_bytes_in_flight;

            $tcp_info{TX}{WIN_SCALE}{$tcp_win_size_scalefactor} ++;
            $tcp_info{ALL}{WIN_SCALE}{$tcp_win_size_scalefactor} ++;

            $tcp_info{TX}{WIN_SIZE}{$tcp_win_size} ++;
            $tcp_info{ALL}{WIN_SIZE}{$tcp_win_size} ++;

            $tcp_info{TX}{PDU_SIZE}{$tcp_pdu_size} ++;
            $tcp_info{ALL}{PDU_SIZE}{$tcp_pdu_size} ++;

            $tcp_info{TX}{CONT}{$tcp_cont} ++;
            $tcp_info{ALL}{CONT}{$tcp_cont} ++;

            $tcp_info{TX}{REUSED_PORT}{$tcp_reused_ports} ++;
            $tcp_info{ALL}{REUSED_PORT}{$tcp_reused_ports} ++;

            print "$tcp_reused_ports\n" if($DEBUG0);
            print "$tcp_cont\n" if($DEBUG0 and $tcp_cont ne "");
            print "$tcp_reused_ports\n" if($DEBUG0 and $tcp_reused_ports != 0);
        }
        elsif($ip_dst eq $ip) {
            ## receiver
            $tcp_info{RX}{CNT} ++;
            $tcp_info{ALL}{CNT} ++;

            ## flags
            print join("|||", ($tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg))."\n" if($DEBUG5);

            if($tcp_flag_ack == 1) {
                $tcp_info{RX}{ACK} ++;
                $tcp_info{ALL}{ACK} ++;
            }
            if($tcp_flag_cwr == 1) {
                $tcp_info{RX}{CWR} ++;
                $tcp_info{ALL}{CWR} ++;
            }
            if($tcp_flag_ecn == 1) {
                $tcp_info{RX}{ECN} ++;
                $tcp_info{ALL}{ECN} ++;
            }
            if($tcp_flag_fin == 1) {
                $tcp_info{RX}{FIN} ++;
                $tcp_info{ALL}{FIN} ++;
            }
            if($tcp_flag_ns == 1) {
                $tcp_info{RX}{NS} ++;
                $tcp_info{ALL}{NS} ++;
            }
            if($tcp_flag_push == 1) {
                $tcp_info{RX}{PUSH} ++;
                $tcp_info{ALL}{PUSH} ++;
            }
            if($tcp_flag_res == 1) {
                $tcp_info{RX}{RES} ++;
                $tcp_info{ALL}{RES} ++;
            }
            if($tcp_flag_reset == 1) {
                $tcp_info{RX}{RESET} ++;
                $tcp_info{ALL}{RESET} ++;
            }
            if($tcp_flag_syn == 1) {
                $tcp_info{RX}{SYN} ++;
                $tcp_info{ALL}{SYN} ++;
            }
            if($tcp_flag_urg == 1) {
                $tcp_info{RX}{URG} ++;
                $tcp_info{ALL}{URG} ++;
            }

            $tcp_info{RX}{LEN}{$tcp_len} ++;
            $tcp_info{RX}{LEN_SUM} += $tcp_len;
            $tcp_info{ALL}{LEN}{$tcp_len} ++;
            $tcp_info{ALL}{LEN_SUM} += $tcp_len;

            if($tcp_opt_kind ne "") {
                my @kinds = split(/,/, $tcp_opt_kind);
                foreach my $kind (@kinds) {
                    $kind += 0;
                    $tcp_info{RX}{OPT_KIND}{$kind} ++;
                    $tcp_info{ALL}{OPT_KIND}{$kind} ++;
                }
                $tcp_info{RX}{NUM_OPT_KIND}{scalar(@kinds)} ++;
                $tcp_info{ALL}{NUM_OPT_KIND}{scalar(@kinds)} ++;
            }
            else {
                $tcp_info{RX}{NUM_OPT_KIND}{0} ++;
                $tcp_info{ALL}{NUM_OPT_KIND}{0} ++;
            }

            $tcp_info{RX}{OPT_LEN}{$tcp_opt_len} ++;
            $tcp_info{RX}{OPT_LEN_SUM} += $tcp_opt_len;
            $tcp_info{ALL}{OPT_LEN}{$tcp_opt_len} ++;
            $tcp_info{ALL}{OPT_LEN_SUM} += $tcp_opt_len;

            $tcp_info{RX}{FLIGHT}{TIME}{$time}{FLIGHT} = $tcp_bytes_in_flight;
            $tcp_info{ALL}{FLIGHT}{TIME}{$time}{FLIGHT} = $tcp_bytes_in_flight;

            $tcp_info{RX}{WIN_SCALE}{$tcp_win_size_scalefactor} ++;
            $tcp_info{ALL}{WIN_SCALE}{$tcp_win_size_scalefactor} ++;

            $tcp_info{RX}{WIN_SIZE}{$tcp_win_size} ++;
            $tcp_info{ALL}{WIN_SIZE}{$tcp_win_size} ++;

            $tcp_info{RX}{PDU_SIZE}{$tcp_pdu_size} ++;
            $tcp_info{ALL}{PDU_SIZE}{$tcp_pdu_size} ++;

            $tcp_info{RX}{CONT}{$tcp_cont} ++;
            $tcp_info{ALL}{CONT}{$tcp_cont} ++;

            $tcp_info{RX}{REUSED_PORT}{$tcp_reused_ports} ++;
            $tcp_info{ALL}{REUSED_PORT}{$tcp_reused_ports} ++;

            print "$tcp_opt_kind\n" if($DEBUG0 and $tcp_opt_kind ne "");
            print "$tcp_reused_ports\n" if($DEBUG0);
            print "$tcp_cont\n" if($DEBUG0 and $tcp_cont ne "");
            print "$tcp_reused_ports\n" if($DEBUG0 and $tcp_reused_ports != 0);
        }

    }

}
close FH;


###############
## output port info
##   %port_info
##   PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
###############
print "Output port info\n" if($DEBUG2);

foreach my $protocol ("UDP", "TCP") {
    foreach my $txrx ("TX", "RX", "ALL") {
        open FH, "> $output_dir/$filename.$protocol.$txrx.txt" or die $!;
        my $first_time = -1;
        foreach my $time (sort {$a <=> $b} (keys %{ $port_info{PORT}{$protocol}{$txrx}{TIME} })) {
            $first_time = $time if($first_time == -1);
            print FH "".($time-$first_time).", ".$port_info{PORT}{$protocol}{$txrx}{TIME}{$time}{PORT}.", ".$port_info{PORT}{$protocol}{$txrx}{TIME}{$time}{LEN}."\n";
        }
        close FH;

        
        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$protocol.$txrx/g; s/FIG_NAME/$filename.$protocol.$txrx/g; s/X_LABEL/time/g; s/Y_LABEL/port/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_port.mother.plot > tmp.$gnuplot_port.$protocol.$txrx.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_port.$protocol.$txrx.plot";
        `$cmd`;
    }
}



###############
## output flag and other info
##   my %tcp_info
##   [TX | RX | ALL] - [CNT | ACK | CWR | ECN | FIN | NS | PUSH | RES | RESET | SYN | URG]
##   [TX | RX | ALL] - [LEN | OPT_KIND | OPT_LEN | FLIGHT | WIN_SCALE | WIN_SIZE | PDU_SIZE | CONT | REUSED_PORT] 
##         - value - count
###############
print "Output TCP flag info\n" if($DEBUG2);
print "  # tx TCP pkts = ".$tcp_info{TX}{CNT}."\n" if($DEBUG3);
print "  # rx TCP pkts = ".$tcp_info{RX}{CNT}."\n" if($DEBUG3);
print "  avg tx len = ".($tcp_info{TX}{LEN_SUM} / $tcp_info{TX}{CNT})."\n";
print "  avg rx len = ".($tcp_info{RX}{LEN_SUM} / $tcp_info{RX}{CNT})."\n";
print "  avg len = ".($tcp_info{ALL}{LEN_SUM} / $tcp_info{ALL}{CNT})."\n";
print "  avg tx opt len = ".($tcp_info{TX}{OPT_LEN_SUM} / $tcp_info{TX}{CNT})."\n";
print "  avg rx opt len = ".($tcp_info{RX}{OPT_LEN_SUM} / $tcp_info{RX}{CNT})."\n";
print "  avg opt len = ".($tcp_info{ALL}{OPT_LEN_SUM} / $tcp_info{ALL}{CNT})."\n";

foreach my $txrx ("TX", "RX", "ALL") {
    ###############
    ## flags
    ###############
    my $out_file_suffix = "tcp_flags.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $flag ("ACK", "FIN", "SYN", "CWR", "ECN", "NS", "PUSH", "RES", "RESET", "URG") {
        $tcp_info{$txrx}{$flag} = 0 unless(exists $tcp_info{$txrx}{$flag});
        print FH "$flag, ".($tcp_info{$txrx}{$flag} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$flag}."\n";
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
    $out_file_suffix = "pkt_len.$txrx";
    my $factor = "LEN";
    ## find top n    
    my @top_n_keys = ();
    foreach my $this_len (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        $tcp_info{$txrx}{$factor} = 0 unless(exists $tcp_info{$txrx}{$factor});
        
        if(scalar(@top_n_keys) < $TOP_N) {
            push(@top_n_keys, $this_len);
        }
        else {
            foreach my $ind (0 .. $TOP_N-1) {
                my $this_key = $top_n_keys[$ind];
                
                if($tcp_info{$txrx}{$factor}{$this_len} > $tcp_info{$txrx}{$factor}{$this_key}) {
                    $top_n_keys[$ind] = $this_len;
                    last;
                }
            }
        }
    }
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_len (sort {$a <=> $b} @top_n_keys) {
        print FH "$this_len, ".($tcp_info{$txrx}{$factor}{$this_len} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_len}."\n";
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
    $out_file_suffix = "tcp_opt_kinds.$txrx";
    $factor = "OPT_KIND";
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_kind (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        print FH "$this_kind, ".($tcp_info{$txrx}{$factor}{$this_kind} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_kind}."\n";
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
    $out_file_suffix = "tcp_opt_kinds_num.$txrx";
    $factor = "NUM_OPT_KIND";
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_num (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        print FH "$this_num, ".($tcp_info{$txrx}{$factor}{$this_num} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_num}."\n";
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
    $out_file_suffix = "opt_len.$txrx";
    $factor = "OPT_LEN";
    ## find top n    
    @top_n_keys = ();
    foreach my $this_len (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        $tcp_info{$txrx}{$factor} = 0 unless(exists $tcp_info{$txrx}{$factor});
        
        if(scalar(@top_n_keys) < $TOP_N) {
            push(@top_n_keys, $this_len);
        }
        else {
            foreach my $ind (0 .. $TOP_N-1) {
                my $this_key = $top_n_keys[$ind];
                
                if($tcp_info{$txrx}{$factor}{$this_len} > $tcp_info{$txrx}{$factor}{$this_key}) {
                    $top_n_keys[$ind] = $this_len;
                    last;
                }
            }
        }
    }
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_len (sort {$a <=> $b} @top_n_keys) {
        print FH "$this_len, ".($tcp_info{$txrx}{$factor}{$this_len} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_len}."\n";
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
    $out_file_suffix = "tcp_bytes_in_flight.$txrx";
    $factor = "FLIGHT";

    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    my $first_time = -1;
    foreach my $time (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor}{TIME} })) {
        $first_time = $time if($first_time == -1);
        print FH "".($time-$first_time).", ".$tcp_info{$txrx}{$factor}{TIME}{$time}{FLIGHT}."\n";
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
    $out_file_suffix = "win_scale.$txrx";
    $factor = "WIN_SCALE";
    ## find top n    
    my @top_n_keys = ();
    foreach my $this_scale (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        $tcp_info{$txrx}{$factor} = 0 unless(exists $tcp_info{$txrx}{$factor});
        
        if(scalar(@top_n_keys) < $TOP_N) {
            push(@top_n_keys, $this_scale);
        }
        else {
            foreach my $ind (0 .. $TOP_N-1) {
                my $this_key = $top_n_keys[$ind];
                
                if($tcp_info{$txrx}{$factor}{$this_scale} > $tcp_info{$txrx}{$factor}{$this_key}) {
                    $top_n_keys[$ind] = $this_scale;
                    last;
                }
            }
        }
    }
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_scale (sort {$a <=> $b} @top_n_keys) {
        print FH "$this_scale, ".($tcp_info{$txrx}{$factor}{$this_scale} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_scale}."\n";
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
    $out_file_suffix = "win_size.$txrx";
    $factor = "WIN_SIZE";
    ## find top n    
    my @top_n_keys = ();
    foreach my $this_size (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        $tcp_info{$txrx}{$factor} = 0 unless(exists $tcp_info{$txrx}{$factor});
        
        if(scalar(@top_n_keys) < $TOP_N) {
            push(@top_n_keys, $this_size);
        }
        else {
            foreach my $ind (0 .. $TOP_N-1) {
                my $this_key = $top_n_keys[$ind];
                
                if($tcp_info{$txrx}{$factor}{$this_size} > $tcp_info{$txrx}{$factor}{$this_key}) {
                    $top_n_keys[$ind] = $this_size;
                    last;
                }
            }
        }
    }
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_size (sort {$a <=> $b} @top_n_keys) {
        print FH "$this_size, ".($tcp_info{$txrx}{$factor}{$this_size} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_size}."\n";
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
    $out_file_suffix = "pdu_size.$txrx";
    $factor = "PDU_SIZE";
    ## find top n    
    my @top_n_keys = ();
    foreach my $this_size (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        $tcp_info{$txrx}{$factor} = 0 unless(exists $tcp_info{$txrx}{$factor});
        
        if(scalar(@top_n_keys) < $TOP_N) {
            push(@top_n_keys, $this_size);
        }
        else {
            foreach my $ind (0 .. $TOP_N-1) {
                my $this_key = $top_n_keys[$ind];
                
                if($tcp_info{$txrx}{$factor}{$this_size} > $tcp_info{$txrx}{$factor}{$this_key}) {
                    $top_n_keys[$ind] = $this_size;
                    last;
                }
            }
        }
    }
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_size (sort {$a <=> $b} @top_n_keys) {
        print FH "$this_size, ".($tcp_info{$txrx}{$factor}{$this_size} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_size}."\n";
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
    $out_file_suffix = "reused_ports.$txrx";
    $factor = "REUSED_PORT";
    ## find top n    
    my @top_n_keys = ();
    foreach my $this_p (sort {$a <=> $b} (keys %{ $tcp_info{$txrx}{$factor} })) {
        $tcp_info{$txrx}{$factor} = 0 unless(exists $tcp_info{$txrx}{$factor});
        
        if(scalar(@top_n_keys) < $TOP_N) {
            push(@top_n_keys, $this_p);
        }
        else {
            foreach my $ind (0 .. $TOP_N-1) {
                my $this_key = $top_n_keys[$ind];
                
                if($tcp_info{$txrx}{$factor}{$this_p} > $tcp_info{$txrx}{$factor}{$this_key}) {
                    $top_n_keys[$ind] = $this_p;
                    last;
                }
            }
        }
    }
    
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $this_p (sort {$a <=> $b} @top_n_keys) {
        print FH "$this_p, ".($tcp_info{$txrx}{$factor}{$this_p} / $tcp_info{$txrx}{CNT}).", ".$tcp_info{$txrx}{$factor}{$this_p}."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;
}







###############
## output IP flag and other info 
##   my %ip_info
##   [TX | RX | ALL] - [CNT | DF | RB | SF]
##   [TX | RX | ALL] - [OPT_LEN | OPT_NUM | DS_CE | DS_DSCP | DS_ECN | DS_ECT | TOS_COST | TOS_DELAY | TOS_PRECEDENCE | TOS_RELIABILITY | TOS_TPUT] 
##         - value - count
###############
print "Output IP flag info\n" if($DEBUG2);
print "  # tx IP pkts = ".$ip_info{TX}{CNT}."\n" if($DEBUG3);
print "  # rx IP pkts = ".$ip_info{RX}{CNT}."\n" if($DEBUG3);

foreach my $txrx ("TX", "RX", "ALL") {
    ###############
    ## flags
    ###############
    my $out_file_suffix = "ip_flags.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $flag ("DF", "RB", "SF") {
        $ip_info{$txrx}{$flag} = 0 unless(exists $ip_info{$txrx}{$flag});
        print FH "$flag, ".($ip_info{$txrx}{$flag} / $ip_info{$txrx}{CNT}).", ".$ip_info{$txrx}{$flag}."\n";
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
    my $out_file_suffix = "ip_option.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $opt_len (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{OPT_LEN} })) {
        print FH "$opt_len, ".($ip_info{$txrx}{OPT_LEN}{$opt_len} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_option_num.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $opt_num (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{OPT_NUM} })) {
        print FH "$opt_num, ".($ip_info{$txrx}{OPT_NUM}{$opt_num} / $ip_info{$txrx}{CNT})."\n";
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
    my $out_file_suffix = "ip_ds_ce.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ds_ce (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{DS_CE} })) {
        print FH "$ds_ce, ".($ip_info{$txrx}{DS_CE}{$ds_ce} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_ds_dscp.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ds_dscp (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{DS_DSCP} })) {
        print FH "$ds_dscp, ".($ip_info{$txrx}{DS_DSCP}{$ds_dscp} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_ds_ecn.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ds_ecn (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{DS_ECN} })) {
        print FH "$ds_ecn, ".($ip_info{$txrx}{DS_ECN}{$ds_ecn} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_ds_ect.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ds_ect (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{DS_ECT} })) {
        print FH "$ds_ect, ".($ip_info{$txrx}{DS_ECT}{$ds_ect} / $ip_info{$txrx}{CNT})."\n";
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
    my $out_file_suffix = "ip_tos_cost.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ip_tos_cost (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{TOS_COST} })) {
        print FH "$ip_tos_cost, ".($ip_info{$txrx}{TOS_COST}{$ip_tos_cost} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_tos_delay.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ip_tos_delay (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{TOS_DELAY} })) {
        print FH "$ip_tos_delay, ".($ip_info{$txrx}{TOS_DELAY}{$ip_tos_delay} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_tos_precedence.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ip_tos_precedence (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{TOS_PRECEDENCE} })) {
        print FH "$ip_tos_precedence, ".($ip_info{$txrx}{TOS_PRECEDENCE}{$ip_tos_precedence} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_tos_reliability.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ip_tos_reliability (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{TOS_RELIABILITY} })) {
        print FH "$ip_tos_reliability, ".($ip_info{$txrx}{TOS_RELIABILITY}{$ip_tos_reliability} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;


    my $out_file_suffix = "ip_tos_throughput.$txrx";
    open FH, "> $output_dir/$filename.$out_file_suffix.txt" or die $!;
    foreach my $ip_tos_throughput (sort {$a <=> $b} (keys %{ $ip_info{$txrx}{TOS_TPUT} })) {
        print FH "$ip_tos_throughput, ".($ip_info{$txrx}{TOS_TPUT}{$ip_tos_throughput} / $ip_info{$txrx}{CNT})."\n";
    }
    close FH;

    print "  gnuplot\n" if($DEBUG2);
    my $cmd = "sed 's/FILE_NAME/$filename.$out_file_suffix/g; s/FIG_NAME/$filename.$out_file_suffix/g; s/X_LABEL//g; s/Y_LABEL/ratio/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/0/g; s/Y_RANGE_E//g; s/DEGREE/-45/g; ' $gnuplot_dist.mother.plot > tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

    $cmd = "gnuplot tmp.$gnuplot_dist.$out_file_suffix.plot";
    `$cmd`;

}


