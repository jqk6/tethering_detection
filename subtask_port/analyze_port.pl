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
##
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


#############
# Constants
#############


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_port/text";
my $output_dir = "../processed_data/subtask_port/analysis";

my $gnuplot_port = "plot_port";

my $ip;
my $filename;

my %port_info = ();  ## PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
my %tcp_info = (); ## [CNT | ACK | CWR | ECN | FIN | NS | PUSH | RES | RESET | SYN | URG]
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

    my ($frame_num, $time, $frame_len, $ip_id, $ip_src, $ip_dst, $udp_sport, $udp_dport, $tcp_sport, $tcp_dport, $tcp_flag_ack, $tcp_flag_cwr, $tcp_flag_ecn, $tcp_flag_fin, $tcp_flag_ns, $tcp_flag_push, $tcp_flag_res, $tcp_flag_reset, $tcp_flag_syn, $tcp_flag_urg, $tcp_len, $tcp_opt_kind, $tcp_opt_len, $tcp_bytes_in_flight, $tcp_win_size_scalefactor, $tcp_win_size, $tcp_pdu_size, $tcp_cont, $tcp_reused_ports) = split(/,/, $_);
    $time += 0; $udp_sport += 0; $udp_dport += 0; $tcp_sport += 0; $tcp_dport += 0;

    ###############
    ## port
    ##   %port_info
    ##   PORT - [UDP | TCP] - [TX | RX | ALL] - TIME - [PORT | LEN]
    ###############
    if($udp_sport != 0) {
        ## UDP
        if($ip_src eq $ip) {
            ## sender
            print "  - UDP tx at $time: port=$udp_sport\n" if($DEBUG4);

            $port_info{PORT}{UDP}{TX}{TIME}{$time}{PORT} = $udp_sport;
            $port_info{PORT}{UDP}{TX}{TIME}{$time}{LEN} = $frame_len;

            $port_info{PORT}{UDP}{ALL}{TIME}{$time}{PORT} = $udp_sport;
            $port_info{PORT}{UDP}{ALL}{TIME}{$time}{LEN} = $frame_len;
        }
        elsif($ip_dst eq $ip) {
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
        $tcp_info{CNT} ++;

        if($ip_src eq $ip) {
            ## sender
            print "  - TCP tx at $time: port=$tcp_sport\n" if($DEBUG4);

            $port_info{PORT}{TCP}{TX}{TIME}{$time}{PORT} = $tcp_sport;
            $port_info{PORT}{TCP}{TX}{TIME}{$time}{LEN} = $frame_len;

            $port_info{PORT}{TCP}{ALL}{TIME}{$time}{PORT} = $tcp_sport;
            $port_info{PORT}{TCP}{ALL}{TIME}{$time}{LEN} = $frame_len;
        }
        elsif($ip_dst eq $ip) {
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
        foreach my $time (sort {$a <=> $b} (keys %{ $port_info{PORT}{$protocol}{$txrx}{TIME} })) {
            print FH "$time, ".$port_info{PORT}{$protocol}{$txrx}{TIME}{$time}{PORT}.", ".$port_info{PORT}{$protocol}{$txrx}{TIME}{$time}{LEN}."\n";
        }
        close FH;

        
        print "  gnuplot\n" if($DEBUG2);
        my $cmd = "sed 's/FILE_NAME/$filename.$protocol.$txrx/g; s/FIG_NAME/$filename.$protocol.$txrx/g; s/X_LABEL/time/g; s/Y_LABEL/port/g; s/Y_LABEL/port/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/Y_RANGE_S//g;' $gnuplot_port.mother.plot > tmp.$gnuplot_port.$protocol.$txrx.plot";
        `$cmd`;

        $cmd = "gnuplot tmp.$gnuplot_port.$protocol.$txrx.plot";
        # `$cmd`;
    }
}
