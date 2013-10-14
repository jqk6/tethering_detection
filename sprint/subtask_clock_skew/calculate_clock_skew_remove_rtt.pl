#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/01 @ Narus
##
## Calculate the clock skew using TCP Timestamp
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
##     a) ./output/
##        file.<ip>.offset.txt:
##        <tx_time> <rx_time> <rx_time_from_1st_pkt> <tx_clock_from_1st_pkt> <tx_time_from_1st_pkt> <offset>
##     b) ./figures
##
## - internal variables
##     a) PLOT_EPS : output eps or png figure
##     b) DEBUG3   : fix the clock frequency of UT machines to 250Hz
##     c) gnuplot  : modify to choose which IPs to plot
##
##  e.g.
##      perl calculate_clock_skew_remove_rtt.pl ../tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt 
##################################################

use strict;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $FIX_UT_FREQ      = 1; ## fix the clock frequency of UT machines to 250Hz
my $FIX_HTC_FREQ     = 1; ## fix the clock frequency of HTC One X to 100Hz
my $FIX_SAMSUNG_FREQ = 1; ## fix the clock frequency of Samsung Tablet to 128Hz
my $FIX_MAC_FREQ     = 1; ## fix the clock frequency of MacBook to 1000Hz
my $PLOT_EPS         = 0; ## 1 to output eps; 0 to output png figure

my $REMOVE_RTT = 1; ## 1 to remove one way delay calculated by TCP Timestamp

#####
## variables
my $output_dir = "./output";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_skew.plot";


my $file_name;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}

my @freq_candidates = (100, 250, 1000);  ## choose the clock frequency as the closest one
# my @freq_candidates = ();
my $freq_threshold = 0.4;           ## the threshold if close to one of the above frequency
my $threshold = 200;                ## only calculate IPs with enough TCP packets


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
my @tmp = split(/\//, $file_name);
my $pure_name = pop(@tmp);
print "input file = $file_name\n" if($DEBUG1);
print "input file name = $pure_name\n" if($DEBUG2);


#####
## main starts here
print STDERR "start to read data..\n" if($DEBUG2);
open FH, "$file_name" or die $!;
# <FH>;
# <FH>;
# <FH>;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);



    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    $ip_info{SRC}{$src}{TS_VAL}{$tcp_ts_val}{RX_TIME_S}{$time}{RX_TIME_US}{$time_usec}{DST}{$dst}{TS_ECR}{$tcp_ts_ecr} = 1;
    $ip_info{SRC}{$src}{DST}{$dst}{TS_ECR}{$tcp_ts_ecr}{RX_TIME_S} = $time;
    $ip_info{SRC}{$src}{DST}{$dst}{TS_ECR}{$tcp_ts_ecr}{RX_TIME_US} = $time_usec;
}
close FH;


#####
## process clock skew
print STDERR "start to process data and generate output..\n" if($DEBUG2);
my $t1 = -1;    ## the first rx timestamp -- the time in seconds at which the measurer observed the i-th packet
my $t1_us = -1;
my $T1 = -1;    ## the first tx timestamp -- the tcp timestamp contained within the i-th packet
my $freq = 0;  ## the TCP timestamp clock frequency
foreach my $this_src (keys %{ $ip_info{SRC} }) {

    next if(scalar(keys %{ $ip_info{SRC}{$this_src}{TS_VAL} }) < $threshold);


    open FH, ">$output_dir/$pure_name.$this_src.offset.rm_rtt.txt" or die $!;
    foreach my $this_ts_val (sort {$a <=> $b} (keys %{ $ip_info{SRC}{$this_src}{TS_VAL} })) {

        foreach my $this_rx_time_s (keys %{ $ip_info{SRC}{$this_src}{TS_VAL}{$this_ts_val}{RX_TIME_S} } ) {
            foreach my $this_rx_time_us (keys %{ $ip_info{SRC}{$this_src}{TS_VAL}{$this_ts_val}{RX_TIME_S}{$this_rx_time_s}{RX_TIME_US} } ) {
                foreach my $this_dst (keys %{ $ip_info{SRC}{$this_src}{TS_VAL}{$this_ts_val}{RX_TIME_S}{$this_rx_time_s}{RX_TIME_US}{$this_rx_time_us}{DST} } ) {
                    foreach my $this_ts_ecr (keys %{ $ip_info{SRC}{$this_src}{TS_VAL}{$this_ts_val}{RX_TIME_S}{$this_rx_time_s}{RX_TIME_US}{$this_rx_time_us}{DST}{$this_dst}{TS_ECR} } ) {


                        my $rtt_s  = 0;
                        my $rtt_us = 0;
                        my $rtt    = 0;
                        
                        if($REMOVE_RTT and exists $ip_info{SRC}{$this_dst}{DST}{$this_src}{TS_ECR}{$this_ts_val}) {
                            my $rtt_s = $ip_info{SRC}{$this_dst}{DST}{$this_src}{TS_ECR}{$this_ts_val}{RX_TIME_S} - $this_rx_time_s;
                            my $rtt_us = $ip_info{SRC}{$this_dst}{DST}{$this_src}{TS_ECR}{$this_ts_val}{RX_TIME_US} - $this_rx_time_us;
                            my $rtt = $rtt_s + $rtt_us / 1000000;                        
                        }


                        ######################################
                        my $this_rx_time_s2 = $this_rx_time_s - $rtt_s / 2;
                        my $this_rx_time_us2 = $this_rx_time_us - $rtt_us / 2;
                        my $this_rx_time2 = $this_rx_time_s2 + $this_rx_time_us2 / 1000000;

                        if($t1 < 0) {
                            $t1 = $this_rx_time_s2;
                            $t1_us = $this_rx_time_us2;
                            $T1 = $this_ts_val;

                            printf("%s first: rx time = %d.%d, tx clock = %d\n", $this_src, $t1, $t1_us, $T1) if($DEBUG1);
                            next;
                        }


                        my $x_s = $this_rx_time_s2 - $t1;
                        my $x_us = $this_rx_time_us2 - $t1_us;
                        my $x = $x_s + $x_us / 1000000;
                        my $v = $this_ts_val - $T1;


                        ## estimate the frequency
                        if($freq == 0) {
                            $freq = $v / $x;

                            foreach my $this_freq (@freq_candidates) {
                                if(abs($freq - $this_freq) < $this_freq * $freq_threshold) {
                                    $freq = $this_freq;
                                    last;
                                }
                            }


                            #####
                            ## XXX: fix it!!
                            $freq = 250  if($this_src =~ /128.83/ and $FIX_UT_FREQ);
                            $freq = 100  if($this_src =~ /10.0.2.5/ and $FIX_HTC_FREQ);
                            $freq = 128  if($this_src =~ /10.0.2.8/ and $FIX_SAMSUNG_FREQ);
                            $freq = 1000 if($this_src =~ /10.0.2.1/ and $FIX_MAC_FREQ);


                            print "frequency of $this_src = $freq\n" if($DEBUG2);
                        }


                        my $w = $v / $freq;
                        my $diff = $x - $w;


                        printf("%s: rx time = %d.%06d, rx interval = %d + %d (%.7f), tx time = %d, tx interval = %d\n", $this_src, $this_rx_time_s2, $this_rx_time_us2, $x_s, $x_us, $x, $this_ts_val, $v) if($DEBUG1);
                        my $tmp = sprintf("%d, %d.%d, %.7f, %d, %.7f, %.7f\n", $this_ts_val, $this_rx_time_s2, $this_rx_time_us2, $x, $v, $w, $diff);
                        print FH $tmp;
                        ######################################

                    }
                }
            }
        }

    }
    close FH;


    $t1 = -1;
    $T1 = -1;
    $freq = 0;
}




#####
## plot
open FH, ">$gnuplot_file" or dir $!;
print FH "reset\n";
if($PLOT_EPS) {
    print FH "set terminal postscript enhanced\n";
}
else {
    print FH "set term pngcairo\n";
}
print FH "set size ratio 0.7\n";
print FH "figure_dir = \"$figure_dir\"\n";
print FH "data_dir = \"$output_dir\"\n";
if($PLOT_EPS) {
    print FH "set output figure_dir.\"\/$pure_name.offset.rm_rtt.eps\"\n";
}
else {
    print FH "set output figure_dir.\"\/$pure_name.offset.rm_rtt.png\"\n";
}
# print FH "set yrange [-0.02:0.02]\n";
print FH "set xlabel \"time (seconds)\"\n";
print FH "set ylabel \"offset\"\n";
print FH "set key Left under reverse nobox spacing 1\n";
print FH "set style line 1 lc rgb \"#FF0000\" lt 1 lw 3\n";
print FH "set style line 2 lc rgb \"#0000FF\" lt 1 lw 3\n";
print FH "set style line 3 lc rgb \"orange\" lt 1 lw 3\n";
print FH "set style line 4 lc rgb \"green\" lt 1 lw 3\n";
print FH "set style line 5 lc rgb \"yellow\" lt 1 lw 3\n";
print FH "set style line 6 lc rgb \"black\" lt 1 lw 3\n";
print FH "plot ";
my $tmp_cnt = 0;
foreach my $this_src (keys %{ $ip_info{SRC} }) {
    
    next if(!($this_src =~ /10\.0/));

    print FH ", \\\n" if($tmp_cnt != 0);
    my $line_cnt = ($tmp_cnt % 6) + 1;
    $tmp_cnt ++;
    print FH "data_dir.\"\/$pure_name.$this_src.offset.rm_rtt.txt\" using 3:6 with points ls $line_cnt title \"$this_src\"";
    # print FH "data_dir.\"\/$pure_name.$this_src.offset.txt\" using 3:6 with points ps 2 ls $line_cnt title \"$this_src\"";
}
close FH;

my $cmd = "gnuplot $gnuplot_file";
`$cmd`;
$cmd = "rm $gnuplot_file";
`$cmd`;
