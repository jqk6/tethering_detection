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
##     c) gnuplot  : modify to choose which IPs to plot
##
##  e.g.
##      perl calculate_clock_skew_sue.pl ../tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt 
##################################################

use strict;

use ClockSkewMoon;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $FIX_UT_FREQ      = 1; ## fix the clock frequency of UT machines to 250Hz
my $FIX_HTC_FREQ     = 1; ## fix the clock frequency of HTC One X to 100Hz
my $FIX_SAMSUNG_FREQ = 1; ## fix the clock frequency of Samsung Tablet to 128Hz
my $FIX_IPHONE_FREQ  = 1; ## fix the clock frequency of iPhone to 1000Hz
my $FIX_IAD_FREQ     = 1; ## fix the clock frequency of iPhone to 1000Hz
my $FIX_MAC_FREQ     = 1; ## fix the clock frequency of MacBook to 1000Hz
my $FIX_OTHER_FREQ   = 1; ## fix the clock frequency of oher machines ...

my $FIX_DEST         = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
# my $FIX_DEST_ADDR    = "192.168.5.67";
# my $FIX_DEST_ADDR    = "199.116.177.167";
# my $FIX_DEST_ADDR    = "10.0.2.1";
# my $FIX_DEST_ADDR    = "69.171.237.20";
# my $FIX_DEST_ADDR    = "64.185.182.185";
# my $FIX_DEST_ADDR    = "128.83.40.144";
# my $FIX_DEST_ADDR    = "128.83.120.139";
my $FIX_DEST_ADDR    = "128.83.143.16";
# my $FIX_DEST_ADDR    = "192.168.4.21";
my $FIX_SRC          = 1;
# my $FIX_SRC_ADDR     = "128.83";
# my $FIX_SRC_ADDR = "128.83.120.139|140.112.30.32|171.67.215.200|23.200.70.151|128.122.119.202|128.97.27.37|128.125.253.146|169.229.216.200|70.97.96.63|128.138.129.98|198.101.129.15|128.95.155.198|141.211.13.226|128.174.180.122|134.84.119.107|129.171.32.100|202.120.2.102|59.106.161.29|222.122.39.176|162.105.131.113|129.206.13.27|131.111.150.25|163.1.60.42|129.78.5.11";
my $FIX_SRC_ADDR = "192.168.1.3|192.168.1.7";

my $PLOT_EPS         = 0; ## 1 to output eps; 0 to output png figure
# my $PLOT_IP          = "192.168.4.78";
# my $PLOT_IP          = "10.0.2.4";
# my $PLOT_IP          = "10.0.2.5";
# my $PLOT_IP          = "10.0.2.8";
# my $PLOT_IP          = "128.83";
my $PLOT_IP          = "\\d+";


#####
## variables
my $output_dir = "./output";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_skew.plot";


my $file_name;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME_S}[receiving time]
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME_US}[receiving time]
                    ## {IP}{ip}{ALPHA}{alpha}
                    ## {IP}{ip}{BETA}{beta}

my @freq_candidates = (10, 100, 250, 1000);  ## choose the clock frequency as the closest one
# my @freq_candidates = ();
my $freq_threshold = 0.4;           ## the threshold if close to one of the above frequency
my $threshold = 10;                ## only calculate IPs with enough TCP packets


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
<FH>;
<FH>;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);



    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;


    next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));
    next if($FIX_SRC  and (!($src =~ /$FIX_SRC_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    # $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_S} = $time;
    # $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_US} = $time_usec;
    push(@{ $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_S} }, $time);
    push(@{ $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_US} }, $time_usec);
}
close FH;

if($DEBUG2) {
    print ">> IPs (".scalar(keys %{ $ip_info{IP} }).")".join(", ", (keys %{ $ip_info{IP} }))."\n";
}


#####
## process clock skew
print STDERR "start to process data and generate output..\n" if($DEBUG2);
my $t1 = -1;    ## the first rx timestamp -- the time in seconds at which the measurer observed the i-th packet
my $t1_us = -1;
my $T1 = -1;    ## the first tx timestamp -- the tcp timestamp contained within the i-th packet
my $freq = 0;  ## the TCP timestamp clock frequency
my $cnt = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    print "\nsize: ".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} })."\n";
    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold);

    $cnt ++;
    print "device $cnt:\n";

    my (@ts, @d);
    open FH, ">$output_dir/$pure_name.$this_ip.offset.txt" or die $!;
    foreach my $this_tx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{TX_TIME} })) {

        foreach my $this_rx_time_ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_S} }-1)) {
            my $this_rx_time_s = $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_S}[$this_rx_time_ind];
            my $this_rx_time_us = $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_US}[$this_rx_time_ind];
            my $this_rx_time = $this_rx_time_s + $this_rx_time_us / 1000000;

            if($t1 < 0) {
                $t1 = $this_rx_time_s;
                $t1_us = $this_rx_time_us;
                $T1 = $this_tx_time;

                printf("%s first: rx time = %d.%06d, tx clock = %d\n", $this_ip, $t1, $t1_us, $T1) if($DEBUG2);
                next;
            }

            my $x_s = $this_rx_time_s - $t1;
            my $x_us = $this_rx_time_us - $t1_us;
            my $x = $x_s + $x_us / 1000000;
            my $v = $this_tx_time - $T1;

            next if($x < 20);

            ## estimate the frequency
            if($freq == 0) {
                $freq = $v / $x;
                my $real_freq = $freq;
                next if($freq == 0);

                foreach my $this_freq (@freq_candidates) {
                    if(abs($freq - $this_freq) < $this_freq * $freq_threshold) {
                        $freq = $this_freq;
                        last;
                    }
                }


                #####
                ## XXX: fix it!!
                # $freq = 250  if($this_ip =~ /128.83/ and $FIX_UT_FREQ);
                $freq = 100  if($this_ip =~ /10.0.2.5/ and $FIX_HTC_FREQ);
                $freq = 128  if($this_ip =~ /10.0.2.8/ and $FIX_SAMSUNG_FREQ);
                $freq = 1000 if($this_ip =~ /10.0.2.7/ and $FIX_IPHONE_FREQ);
                $freq = 1000 if($this_ip =~ /10.0.2.4/ and $FIX_IPHONE_FREQ);
                $freq = 1000 if($this_ip =~ /10.0.2.6/ and $FIX_IAD_FREQ);
                $freq = 128  if($this_ip =~ /192.168.4.78/ and $FIX_OTHER_FREQ);


                print "frequency of $this_ip (".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }).") = $freq ($real_freq)\n" if($DEBUG2);
            }


            my $w = $v / $freq;
            my $diff = $x - $w;
            # push(@ts, $w);
            push(@ts, $x);
            push(@d, $diff);


            printf("%s: rx time = %d.%06d, rx interval = %d + %d (%.7f), tx time = %d, tx interval = %d\n", $this_ip, $this_rx_time_s, $this_rx_time_us, $x_s, $x_us, $x, $this_tx_time, $v) if($DEBUG1);
            my $tmp = sprintf("%d, %d.%06d, %.7f, %d, %.7f, %.7f\n", $this_tx_time, $this_rx_time_s, $this_rx_time_us, $x, $v, $w, $diff);
            print FH $tmp;
        }
    }
    close FH;

    my ($alpha, $beta) = ClockSkewMoon::clock_skew_moon(\@d, \@ts);
    $ip_info{IP}{$this_ip}{ALPHA} = $alpha;
    $ip_info{IP}{$this_ip}{BETA} = $beta;
    print join(", ", ($alpha, $beta))."\n";


    $t1 = -1;
    $T1 = -1;
    $freq = 0;
}




#####
## plot
print STDERR "start to plot..\n" if($DEBUG2);
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
# print FH "set yrange [-10:1000]\n";
print FH "set xlabel \"time (seconds)\"\n";
print FH "set ylabel \"offset\"\n";
# print FH "set key Left under reverse nobox spacing 1\n";
print FH "set nokey\n";
print FH "set style line 1 lc rgb \"#0000FF\" lt 1 lw 3\n";
print FH "set style line 2 lc rgb \"#FF0000\" lt 1 lw 5\n";
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
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.5/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.8/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.7/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.1/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.4/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /192.168.4.78/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /192.168.5.67/));
    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /$PLOT_IP/));


    print FH ", \\\n" if($tmp_cnt != 0);
    my $line_cnt = ($tmp_cnt % 6) + 1;
    $tmp_cnt ++;
    print FH "data_dir.\"\/$pure_name.$this_ip.offset.txt\" using 3:6 with points ls $line_cnt title \"$this_ip\"";
 
    ## regression
    if(exists $ip_info{IP}{$this_ip}{ALPHA}) {
        $line_cnt = ($tmp_cnt % 6) + 1;
        $tmp_cnt ++;

        print FH ", \\\n";
        print FH $ip_info{IP}{$this_ip}{ALPHA}."*x - ".$ip_info{IP}{$this_ip}{BETA}." ls $line_cnt notitle";
    }
}
close FH;

my $cmd = "gnuplot $gnuplot_file";
`$cmd`;
$cmd = "rm $gnuplot_file";
# `$cmd`;
