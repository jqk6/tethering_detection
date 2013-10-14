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
##      perl calculate_clock_skew.pl ../tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt 
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
my $PLOT_EPS         = 0; ## 1 to output eps; 0 to output png figure

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


    next if(exists $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val});

    # $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME} = $time + $time_usec / 1000000;
    $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_S} = $time;
    $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_US} = $time_usec;
}
close FH;


#####
## process clock skew
print STDERR "start to process data and generate output..\n" if($DEBUG2);
my $t1 = -1;    ## the first rx timestamp -- the time in seconds at which the measurer observed the i-th packet
my $t1_us = -1;
my $T1 = -1;    ## the first tx timestamp -- the tcp timestamp contained within the i-th packet
my $freq = 0;  ## the TCP timestamp clock frequency
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold);

    open FH, ">$output_dir/$pure_name.$this_ip.offset.txt" or die $!;
    foreach my $this_tx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{TX_TIME} })) {
        # my $this_rx_time = $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME};
        my $this_rx_time_s = $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_S};
        my $this_rx_time_us = $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_US};
        my $this_rx_time = $this_rx_time_s + $this_rx_time_us / 1000000;

        if($t1 < 0) {
            $t1 = $this_rx_time_s;
            $t1_us = $this_rx_time_us;
            $T1 = $this_tx_time;

            printf("%s first: rx time = %d.%d, tx clock = %d\n", $this_ip, $t1, $t1_us, $T1) if($DEBUG1);
            next;
        }

        my $x_s = $this_rx_time_s - $t1;
        my $x_us = $this_rx_time_us - $t1_us;
        my $x = $x_s + $x_us / 1000000;
        my $v = $this_tx_time - $T1;


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
            $freq = 250 if($this_ip =~ /128.83/ and $FIX_UT_FREQ);
            $freq = 100 if($this_ip =~ /10.0.2.5/ and $FIX_HTC_FREQ);
            $freq = 128 if($this_ip =~ /10.0.2.8/ and $FIX_SAMSUNG_FREQ);


            print "frequency of $this_ip (".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }).") = $freq\n" if($DEBUG2);
        }


        my $w = $v / $freq;
        my $diff = $x - $w;


        printf("%s: rx time = %d.%06d, rx interval = %d + %d (%.7f), tx time = %d, tx interval = %d\n", $this_ip, $this_rx_time_s, $this_rx_time_us, $x_s, $x_us, $x, $this_tx_time, $v) if($DEBUG1);
        my $tmp = sprintf("%d, %d.%d, %.7f, %d, %.7f, %.7f\n", $this_tx_time, $this_rx_time_s, $this_rx_time_us, $x, $v, $w, $diff);
        print FH $tmp;
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
    print FH "set output figure_dir.\"\/$pure_name.eps\"\n";
}
else {
    print FH "set output figure_dir.\"\/$pure_name.png\"\n";
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
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /128\.83/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /128\.83/ or $this_ip =~ /192\.168/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /192\.168/));
    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10\.0/));

    print FH ", \\\n" if($tmp_cnt != 0);
    my $line_cnt = ($tmp_cnt % 6) + 1;
    $tmp_cnt ++;
    print FH "data_dir.\"\/$pure_name.$this_ip.offset.txt\" using 3:6 with points ls $line_cnt title \"$this_ip\"";
    # print FH "data_dir.\"\/$pure_name.$this_ip.offset.txt\" using 3:6 with points ps 2 ls $line_cnt title \"$this_ip\"";
}
close FH;

my $cmd = "gnuplot $gnuplot_file";
`$cmd`;
$cmd = "rm $gnuplot_file";
`$cmd`;
