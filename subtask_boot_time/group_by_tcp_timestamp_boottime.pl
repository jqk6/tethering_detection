#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/18 @ Narus
##
## Calculate the boot time using TCP Timestamp option
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
##     a) ./output_boot_time/
##        file.<ip>.boot_time.txt:
##        <normalized tcp timestamp>
##     b) ./output_boot_time/
##        file.boot_time.txt:
##        The boot time of all IPs
##        <normalized tcp timestamp>
##     c) ./figures_boot_time/
##        file.boot_time.eps:
##
## - internal variables
##     a) FIX_FREQ  : fix the clock frequency of UT machines to 250Hz
##     b) PLOT_EPS  : output eps or png figure
##     c) PLOT_LOGX : plot the log x in gnuplot
##     d) gnuplot   : modify to choose which IPs to plot
##     e) FIX_DEST  : only target the pkts to some destination node
##     f) THRESHOLD : only IP with # of pkts > THRESHOLD will be analyzed
##
##  e.g.
##      perl group_by_tcp_timestamp_boottime.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt
##################################################

use strict;

use MyUtil;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $FIX_FREQ      = 1; ## fix frequency
my $PLOT_EPS      = 1; ## 1 to output eps; 0 to output png figure
my $PLOT_LOGX     = 0; ## 1 to plot log x; 0 otherwise

my $FIX_DEST      = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DEST_ADDR = "192.168.5.67";

## The IP to be plotted
# my $PLOT_IP       = "10.0.2.4"; 
# my $PLOT_IP       = "128.83";
my $PLOT_IP       = "192.168";

my $THRESHOLD     = 4000;

#####
## variables
my $output_dir = "./output_boot_time";
my $figure_dir = "./figures_boot_time";
my $gnuplot_file = "plot_boot_time.plot";

my $file_name;
# my $target_ip;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}
                    ## {IP}{ip}{BOOT_TIME}{values}



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
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);

    ## convert string to numbers
    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;


    next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME} = $time + $time_usec / 1000000;
}
close FH;


#####
## Calculate boot time
print STDERR "start to process data..\n" if($DEBUG2);
my $freq = 0;  ## the TCP timestamp clock frequency
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD);


    ## estimate the frequency
    ## XXX: fix it!!
    if($FIX_FREQ) {
        $freq = 250  if($this_ip =~ /128.83/);
        $freq = 100  if($this_ip =~ /10.0.2.5/);
        $freq = 128  if($this_ip =~ /10.0.2.8/);
        $freq = 1000 if($this_ip =~ /10.0.2.7/);
        $freq = 1000 if($this_ip =~ /10.0.2.4/);
        $freq = 1000 if($this_ip =~ /10.0.2.6/);
        $freq = 1000  if($this_ip =~ /192.168.4.78/);
    }
    if($freq == 0) {
        $freq = 1000;
    }
    print "frequency of $this_ip (".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }).") = $freq\n" if($DEBUG2);


    my $min_boot_time = -1;
    my $max_boot_time = -1;
    foreach my $this_tx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{TX_TIME} })) {
        my $this_rx_time = $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME};
        my $boot_time = $this_rx_time - $this_tx_time / $freq;


        ## statistic of the boot time of the IP
        if($min_boot_time < 0 or $boot_time < $min_boot_time) {
            $min_boot_time = $boot_time;
        }
        if($max_boot_time < 0 or $boot_time > $max_boot_time) {
            $max_boot_time = $boot_time;
        }
        

        ## store the boot time for later
        push( (@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }), $boot_time );        
    }


    ## statistic of the boot time of the IP
    $ip_info{IP}{$this_ip}{MIN_BOOT_TIME} = $min_boot_time;
    $ip_info{IP}{$this_ip}{MAX_BOOT_TIME} = $max_boot_time;
    $ip_info{IP}{$this_ip}{AVG_BOOT_TIME} = MyUtil::average(\@{ $ip_info{IP}{$this_ip}{BOOT_TIME} });
    $ip_info{IP}{$this_ip}{STDEV_BOOT_TIME} = MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{BOOT_TIME} });

}


#####
## Print out boot times
print STDERR "start to generate output..\n" if($DEBUG2);
open FH_ALL, ">$output_dir/$pure_name.boot_time.txt" or die $!;
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD);

    open FH, ">$output_dir/$pure_name.$this_ip.boot_time.txt" or die $!;
    foreach my $this_value (@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }) {
        print FH $this_value.", 0\n";
        print FH_ALL $this_value.", 0\n";
    }
    close FH;
}
close FH_ALL;

open FH, ">$output_dir/$pure_name.boot_time.log" or die $!;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD);

    print FH "$this_ip: \n";
    print FH "  min: ".$ip_info{IP}{$this_ip}{MIN_BOOT_TIME}."\n";
    print FH "  max: ".$ip_info{IP}{$this_ip}{MAX_BOOT_TIME}."\n";
    print FH "  interval: ".($ip_info{IP}{$this_ip}{MAX_BOOT_TIME} - $ip_info{IP}{$this_ip}{MIN_BOOT_TIME})."\n";
    print FH "  avg: ".$ip_info{IP}{$this_ip}{AVG_BOOT_TIME}."\n";
    print FH "  stdev: ".$ip_info{IP}{$this_ip}{STDEV_BOOT_TIME}."\n\n";
}
close FH;


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
    print FH "set output figure_dir.\"\/$pure_name.boot_time.eps\"\n";
}
else {
    print FH "set output figure_dir.\"\/$pure_name.boot_time.png\"\n";
}
# print FH "set yrange [-0.01:0.01]\n";
print FH "set xlabel \"Boot Time (sec)\"\n";
if($PLOT_LOGX) {
    print FH "set logscale x\n";
}
print FH "set key Left under reverse nobox spacing 2\n";
print FH "set xtics rotate by 315\n";

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
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD or !($this_ip =~ /128\.83/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD or !($this_ip =~ /128\.83/ or $this_ip =~ /192\.168/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD or !($this_ip =~ /192\.168/));
    # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD or !($this_ip =~ /10\.0/));
    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD or !($this_ip =~ /$PLOT_IP/));

    print FH ", \\\n" if($tmp_cnt != 0);
    my $line_cnt = ($tmp_cnt % 12) + 1;
    $tmp_cnt ++;
    print FH "data_dir.\"\/$pure_name.$this_ip.boot_time.txt\" using 1:2 with points ls $line_cnt title \"$this_ip\"";
}
close FH;

my $cmd = "gnuplot $gnuplot_file";
`$cmd`;
$cmd = "rm $gnuplot_file";
`$cmd`;