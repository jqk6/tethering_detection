#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/08 @ Narus
##
## Calculate the boot time using TCP Timestamp option
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
##     a) ./output/
##        file.<ip>.group.txt:
##        <normalized tcp timestamp>
##     b) ./output/
##        file.group.txt:
##        The boot time of all IPs
##        <normalized tcp timestamp>
##     c) ./figures/
##        file.group.eps:
##
## - internal variables
##     a) PLOT_EPS : output eps or png figure
##     b) DEBUG3   : fix the clock frequency of UT machines to 250Hz
##     c) gnuplot  : modify to choose which IPs to plot
##
##  e.g.
##      perl group_by_tcp_timestamp.pl ~/testbed/
##################################################

use strict;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug
my $DEBUG3 = 1; ## force frequency to 250 for UT machines

my $PLOT_EPS  = 0; ## 1 to output eps; 0 to output png figure
my $PLOT_LOGX = 1; ## 1 to plot log x; 0 otherwise


#####
## variables
my $output_dir = "./output";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_group.plot";

my $file_name;
# my $target_ip;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}
                    ## {IP}{ip}{GROUP}{values}
my @freq_candidates = (100, 250, 1000);
my $freq_threshold = 0.4;
my $threshold = 200;


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
my $smallest_rx_time = -1;
my $smallest_tx_time = -1;
print STDERR "start to read data..\n" if($DEBUG2);
open FH, "$file_name" or die $!;
<FH>;
<FH>;
<FH>;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);


    # next if(!($src eq $target_ip));


    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    next if(exists $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val});

    $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME} = $time + $time_usec / 1000000;

    if($smallest_rx_time < 0 or $smallest_rx_time > $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME}) {
        $smallest_rx_time = $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME};
        $smallest_tx_time = $tcp_ts_val;
    }
}
close FH;


#####
## process clock skew
print STDERR "start to process data and generate output..\n" if($DEBUG2);
my $t1 = -1;    ## the first rx timestamp -- the time in seconds at which the measurer observed the i-th packet
my $T1 = -1;    ## the first tx timestamp -- the tcp timestamp contained within the i-th packet
my $freq = 0;  ## the TCP timestamp clock frequency
my $min_value = -1;
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold);

    foreach my $this_tx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{TX_TIME} })) {
        my $this_rx_time = $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME};

        if($t1 < 0) {
            $t1 = $this_rx_time;
            $T1 = $this_tx_time;
            next;
        }

        my $x = $this_rx_time - $t1;
        my $v = $this_tx_time - $T1;

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
            $freq = 250 if($this_ip =~ /128\.83/ and $DEBUG3);


            print "frequency of $this_ip (".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }).") = $freq\n" if($DEBUG2);
        }


        my $new_value = $this_tx_time - ($this_rx_time - $smallest_rx_time) * $freq;
        if($min_value < 0 or $new_value < $min_value) {
            $min_value = $new_value;
        }
        push( (@{ $ip_info{IP}{$this_ip}{GROUP} }), $new_value );
        
    }
    


    $t1 = -1;
    $T1 = -1;
    $freq = 0;
}

open FH_ALL, ">$output_dir/$pure_name.group.txt" or die $!;
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold);

    open FH, ">$output_dir/$pure_name.$this_ip.group.txt" or die $!;
    foreach my $this_value (@{ $ip_info{IP}{$this_ip}{GROUP} }) {
        print FH ($this_value - $min_value).", 0\n";
        print FH_ALL ($this_value - $min_value).", 0\n";
    }
    close FH;
}
close FH_ALL;


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
print FH "set size ratio 0.3\n";
print FH "figure_dir = \"$figure_dir\"\n";
print FH "data_dir = \"$output_dir\"\n";
if($PLOT_EPS) {
    print FH "set output figure_dir.\"\/$pure_name.group.eps\"\n";
}
else {
    print FH "set output figure_dir.\"\/$pure_name.group.png\"\n";
}
print FH "set yrange [-0.01:0.01]\n";
print FH "set xlabel \"Timestamp\"\n";
if($PLOT_LOGX) {
    print FH "set logscale x\n";
}
print FH "set key Left under reverse nobox spacing 2\n";
# print FH "set style line 1 lc rgb \"#FF0000\" ps 2 pt 3 lt 1 lw 3\n";
print FH "set style line 1 lc rgb \"#FF0000\" ps 2 lt 1 lw 3\n";
print FH "set style line 2 lc rgb \"#0000FF\" ps 2 lt 1 lw 3\n";
print FH "set style line 3 lc rgb \"orange\" ps 2 lt 1 lw 3\n";
print FH "set style line 4 lc rgb \"green\" ps 2 lt 1 lw 3\n";
print FH "set style line 5 lc rgb \"yellow\" ps 2 lt 1 lw 3\n";
print FH "set style line 6 lc rgb \"black\" ps 2 lt 1 lw 3\n";
print FH "set style line 7 lc rgb \"#FF0000\" ps 2 lt 1 lw 3\n";
print FH "set style line 8 lc rgb \"#0000FF\" ps 2 lt 1 lw 3\n";
print FH "set style line 9 lc rgb \"orange\" ps 2 lt 1 lw 3\n";
print FH "set style line 10 lc rgb \"green\" ps 2 lt 1 lw 3\n";
print FH "set style line 11 lc rgb \"yellow\" ps 2 lt 1 lw 3\n";
print FH "set style line 12 lc rgb \"black\" ps 2 lt 1 lw 3\n";
print FH "plot ";
my $tmp_cnt = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /128\.83/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /128\.83/ or $this_ip =~ /192\.168/));
    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /192\.168/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10\.0/));

    print FH ", \\\n" if($tmp_cnt != 0);
    my $line_cnt = ($tmp_cnt % 12) + 1;
    $tmp_cnt ++;
    print FH "data_dir.\"\/$pure_name.$this_ip.group.txt\" using 1:2 with points ls $line_cnt title \"$this_ip\"";
}
close FH;

my $cmd = "gnuplot $gnuplot_file";
`$cmd`;
$cmd = "rm $gnuplot_file";
`$cmd`;