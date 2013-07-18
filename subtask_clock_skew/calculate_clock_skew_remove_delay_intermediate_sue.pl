#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/16 @ Narus
##
## Calculate the clock skew using TCP Timestamp, need an intermediate node to remove one way delay
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
##      perl calculate_clock_skew_remove_delay_intermediate_sue.pl ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.intermediate_node_wired.pcap.txt ~/testbed/tcp_traces/text5/2013.07.15.Samsung.iperf.2nd_trace.dest_node.pcap.txt
##################################################

use strict;

use ClockSkewMoon;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $PLOT_EPS = 1; ## 1 to output eps; 0 to output png figure
my $FIX_FREQ = 1; ## fix the clock frequency

my $FIX_DEST = 1; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DEST_ADDR = "192.168.5.67";



#####
## variables
my $output_dir = "./output";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_skew.plot";


my $file_name_intermediate;
my $file_name_dest;

my %ip_info;        ## IP
                    ## {DEST_IP}        {ip}{TX_TIME}{sending time}{RX_TIME_S} [receiving times (sec)]
                    ## {DEST_IP}        {ip}{TX_TIME}{sending time}{RX_TIME_US}[receiving times (us) ]
                    ## {DEST_IP}        {ip}{TX_TIME}{sending time}{SEQ_ACK_ID}    [sequency num:ack num ]
                    ## {INTERMEDIATE_IP}{ip}{TX_TIME}{sending time}{RX_TIME_S} [receiving times (sec)]
                    ## {INTERMEDIATE_IP}{ip}{TX_TIME}{sending time}{RX_TIME_US}[receiving times (us) ]
                    ## {INTERMEDIATE_IP}{ip}{TX_TIME}{sending time}{SEQ_ACK_ID}    [sequency num:ack num ]
                    
                    ## {INTERMEDIATE_IP}{ip}{SEQ_ACK_ID}{sequency num:ack num}{TX_TIME}{sending time}{RX_TIME_S}{receiving times (sec)}{RX_TIME_US}{receiving times (us)}
                    
                    ## {DEST_IP}{ip}{ALPHA}{alpha}
                    ## {DEST_IP}{ip}{BETA}{beta}
                    ## {INTERMEDIATE_IP}{ip}{ALPHA}{alpha}
                    ## {INTERMEDIATE_IP}{ip}{BETA}{beta}

my $threshold = 50;                ## only calculate IPs with enough TCP packets


#####
## check input
if(@ARGV != 2) {
    print "wrong number of input\n";
    exit;
}
$file_name_intermediate = $ARGV[0];
my @tmp = split(/\//, $file_name_intermediate);
my $pure_name_intermediate = pop(@tmp);
print "input intermediate file = $file_name_intermediate\n" if($DEBUG1);
print "input intermediate file name = $pure_name_intermediate\n" if($DEBUG2);

$file_name_dest         = $ARGV[1];
@tmp = split(/\//, $file_name_dest);
my $pure_name_dest = pop(@tmp);
print "input file = $file_name_dest\n" if($DEBUG1);
print "input file name = $pure_name_dest\n" if($DEBUG2);


#####
## main starts here
print STDERR "start to read intermediate node data..\n" if($DEBUG2);
open FH, "$file_name_intermediate" or die $!;
# <FH>;
# <FH>;
# <FH>;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);

    ## convert from string to number
    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;


    next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    ## {INTERMEDIATE_IP}{ip}{TX_TIME}{sending time}{RX_TIME_S} [receiving times (sec)]
    ## {INTERMEDIATE_IP}{ip}{TX_TIME}{sending time}{RX_TIME_US}[receiving times (us) ]
    ## {INTERMEDIATE_IP}{ip}{TX_TIME}{sending time}{SEQ_ACK_ID}[sequency num:ack num ]
    push(@{ $ip_info{INTERMEDIATE_IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_S} }, $time);
    push(@{ $ip_info{INTERMEDIATE_IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_US} }, $time_usec);
    push(@{ $ip_info{INTERMEDIATE_IP}{$src}{TX_TIME}{$tcp_ts_val}{SEQ_ACK_ID} }, "$seq:$ack:$id");

    ## {INTERMEDIATE_IP}{ip}{SEQ_ACK_ID}{sequency num:ack num}{TX_TIME}{sending time}{RX_TIME_S}{receiving times (sec)}{RX_TIME_US}{receiving times (us)}
    if(exists $ip_info{INTERMEDIATE_IP}{$src}{SEQ_ACK_ID}{"$seq:$ack:$id"}) {
        my @tmp = (keys %{ $ip_info{INTERMEDIATE_IP}{$src}{SEQ_ACK_ID} });
        my $existed_seq_ack  = pop @tmp;
        @tmp = (keys %{ $ip_info{INTERMEDIATE_IP}{$src}{SEQ_ACK_ID}{"$seq:$ack:$id"}{TX_TIME} });
        my $existed_timestamp  = pop @tmp;
        @tmp = keys %{ $ip_info{INTERMEDIATE_IP}{$src}{SEQ_ACK_ID}{"$seq:$ack:$id"}{TX_TIME}{$existed_timestamp}{RX_TIME_S} };
        my $existed_rx_time_s  = pop @tmp;
        @tmp = keys %{ $ip_info{INTERMEDIATE_IP}{$src}{SEQ_ACK_ID}{"$seq:$ack:$id"}{TX_TIME}{$existed_timestamp}{RX_TIME_S}{$existed_rx_time_s}{RX_TIME_US} };
        my $existed_rx_time_us = pop @tmp;
        
        die "$seq:$ack is already there: \n".
              "  seq_ack: $existed_seq_ack\n".
              "  timestamp: $existed_timestamp\n".
              "  rx time  : ".($existed_rx_time_s + $existed_rx_time_us / 1000000)."\n\n".
              "new: \n".
              "  seq_ack: $seq:$ack:$id\n".
              "  timestamp: $tcp_ts_val\n".
              "  rx time  : ".($time + $time_usec / 1000000)."\n\n";
    }
    $ip_info{INTERMEDIATE_IP}{$src}{SEQ_ACK_ID}{"$seq:$ack:$id"}
                                   {TX_TIME}{$tcp_ts_val}
                                   {RX_TIME_S}{$time}
                                   {RX_TIME_US}{$time_usec} = 1;
}
close FH;


print STDERR "start to read dest node data..\n" if($DEBUG2);
open FH, "$file_name_dest" or die $!;
# <FH>;
# <FH>;
# <FH>;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr) = split(/\s+>*\s*/, $_);

    ## convert from string to number
    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $tcp_ts_val += 0; $tcp_ts_ecr += 0;


    next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    ## {DEST_IP}{ip}{TX_TIME}{sending time}{RX_TIME_S} [receiving times (sec)]
    ## {DEST_IP}{ip}{TX_TIME}{sending time}{RX_TIME_US}[receiving times (us) ]
    ## {DEST_IP}{ip}{TX_TIME}{sending time}{SEQ_ACK_ID}[sequency num:ack num ]
    push(@{ $ip_info{DEST_IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_S} }, $time);
    push(@{ $ip_info{DEST_IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME_US} }, $time_usec);
    push(@{ $ip_info{DEST_IP}{$src}{TX_TIME}{$tcp_ts_val}{SEQ_ACK_ID} }, "$seq:$ack:$id");
}
close FH;


#####
## process clock skew
print STDERR "start to process data and generate output..\n" if($DEBUG2);
my $t1 = -1;    ## the first rx timestamp -- the time in seconds at which the measurer observed the i-th packet
my $ta1 = -1;    ## the first rx timestamp of the intermediate node
my $dab1 = -1;    ## the first delay between intermediate node and destination node
my $T1 = -1;    ## the first tx timestamp -- the tcp timestamp contained within the i-th packet
my $freq = 0;  ## the TCP timestamp clock frequency

foreach my $this_ip (keys %{ $ip_info{DEST_IP} }) {

    ## ignore IPs who only have a few packets
    next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold);


    ## estimate the frequency
    ## XXX: fix it!!
    if($FIX_FREQ) {
        $freq = 250  if($this_ip =~ /128.83/);
        $freq = 100  if($this_ip =~ /10.0.2.5/);
        $freq = 128  if($this_ip =~ /10.0.2.8/);
        $freq = 1000 if($this_ip =~ /10.0.2.7/);
        $freq = 1000 if($this_ip =~ /10.0.2.4/);
        $freq = 1000 if($this_ip =~ /10.0.2.6/);
        $freq = 128  if($this_ip =~ /192.168.4.78/);
    }
    if($freq == 0) {
        $freq = 1000;
    }
    print "frequency of $this_ip (".scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }).") = $freq\n" if($DEBUG2);


    my (@ts, @d);   ## used for Moon Sue's clock skew estimation algorithm
    my %ts;         ## used to avoid duplicate in @ts
    open FH, ">$output_dir/$pure_name_dest.$this_ip.offset.txt" or die $!;
    foreach my $this_tx_time (sort {$a <=> $b} (keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} })) {

        foreach my $this_rx_time_ind (0 .. scalar(@{ $ip_info{DEST_IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_S} }-1)) {
            my $this_rx_time_s = $ip_info{DEST_IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_S}[$this_rx_time_ind];
            my $this_rx_time_us = $ip_info{DEST_IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME_US}[$this_rx_time_ind];
            my $this_rx_time = $this_rx_time_s + $this_rx_time_us / 1000000;
            my $this_seq_ack = $ip_info{DEST_IP}{$this_ip}{TX_TIME}{$this_tx_time}{SEQ_ACK_ID}[$this_rx_time_ind];
            

            ## check if intermediate node has this packet
            ## {INTERMEDIATE_IP}{ip}{SEQ_ACK_ID}{sequency num:ack num}{TX_TIME}{sending time}{RX_TIME_S}{receiving times (sec)}{RX_TIME_US}{receiving times (us)}
            next if(!(exists $ip_info{INTERMEDIATE_IP}{$this_ip}{SEQ_ACK_ID}{$this_seq_ack}));
            my @tmps = keys (%{ $ip_info{INTERMEDIATE_IP}{$this_ip}{SEQ_ACK_ID}{$this_seq_ack}{TX_TIME} });
            die "should just have one tx time for each seq_ack\n" if(scalar @tmps > 1);
            my $this_intermediate_tx_time = pop(@tmps);
            die "the timestamp from intermediate and dest node are different\n".
                "  intermediate: $this_intermediate_tx_time\n".
                "  dest        : $this_tx_time\n" if($this_tx_time != $this_intermediate_tx_time);

            @tmps = keys (%{ $ip_info{INTERMEDIATE_IP}{$this_ip}{SEQ_ACK_ID}{$this_seq_ack}{TX_TIME}{$this_intermediate_tx_time}{RX_TIME_S} });
            die "should just have one rx time (s) for each seq_ack\n" if(scalar @tmps > 1);
            my $this_intermediate_rx_time_s = pop(@tmps);

            @tmps = keys (%{ $ip_info{INTERMEDIATE_IP}{$this_ip}{SEQ_ACK_ID}{$this_seq_ack}{TX_TIME}{$this_intermediate_tx_time}{RX_TIME_S}{$this_intermediate_rx_time_s}{RX_TIME_US} });
            die "should just have one rx time (us) for each seq_ack\n" if(scalar @tmps > 1);
            my $this_intermediate_rx_time_us = pop(@tmps);
            my $this_intermediate_rx_time = $this_intermediate_rx_time_s + $this_intermediate_rx_time_us / 1000000;
            
            printf("-----------\ntx timestamp: %d\n", $this_tx_time) if($DEBUG1);
            printf("rx time: %.7f\n", $this_rx_time) if($DEBUG1);
            printf("intermediate node rx time: %.7f\n", $this_intermediate_rx_time) if($DEBUG1);


            if($ta1 < 0) {
                $ta1 = $this_intermediate_rx_time;
                $T1 = $this_tx_time;
                $dab1 = $this_rx_time - $this_intermediate_rx_time;
                
                printf("%s intermediate node first: rx time = %d.%06d\n", $this_ip, $this_intermediate_rx_time_s, $this_intermediate_rx_time_us) if($DEBUG1);
                printf("%s intermediate node first: rx time = %.7f\n", $this_ip, $this_intermediate_rx_time) if($DEBUG1);
            }


            ##############
            ## remove one way delay

            ## - method 1
            # $this_rx_time_s = $this_intermediate_rx_time_s;
            # $this_rx_time_us = $this_intermediate_rx_time_us;
            # $this_rx_time = $this_intermediate_rx_time;

            ## - method 2
            my $this_dab = $this_rx_time - $this_intermediate_rx_time;
            my $one_way_delay = $this_intermediate_rx_time - $ta1 - ($this_tx_time - $T1) / $freq;
            # my $one_way_delay = $this_intermediate_rx_time - $ta1 - ($this_tx_time - $T1) / $freq + ($this_dab - $dab1);
            # my $one_way_delay = $this_intermediate_rx_time - $ta1 - ($this_tx_time - $T1) / $freq + ($this_dab);
            # my $one_way_delay = $this_dab;
            $this_rx_time -= $one_way_delay;
            printf("one way delay = %.7f\n", $one_way_delay) if($DEBUG1);
            printf("rx time becomes: %.7f\n", $this_rx_time) if($DEBUG1);
            

            if($t1 < 0) {
                $t1 = $this_rx_time;

                printf("%s first: rx time = %.7f, tx clock = %d\n", $this_ip, $t1, $T1) if($DEBUG1);
                next;
            }

            my $x = $this_rx_time - $t1;
            my $v = $this_tx_time - $T1;

            my $w = $v / $freq;
            my $diff = $x - $w;
            
            next if(exists $ts{$x});
            push(@ts, $x);
            push(@d, $diff);
            $ts{$x} = 1;


            printf("%s: rx time = %.7f, rx interval = %.7f, tx time = %d, tx interval = %d\n", $this_ip, $this_rx_time, $x, $this_tx_time, $v) if($DEBUG1);
            my $tmp = sprintf("%d, %.7f, %.7f, %d, %.7f, %.7f\n", $this_tx_time, $this_rx_time, $x, $v, $w, $diff);
            print FH $tmp;
        }
    }
    close FH;

    my ($alpha, $beta) = ClockSkewMoon::clock_skew_moon(\@d, \@ts);
    $ip_info{DEST_IP}{$this_ip}{ALPHA} = $alpha;
    $ip_info{DEST_IP}{$this_ip}{BETA} = $beta;
    print join(", ", ($alpha, $beta))."\n";


    $t1 = -1;
    $ta1 = -1;
    $T1 = -1;
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
    print FH "set output figure_dir.\"\/$pure_name_dest.eps\"\n";
}
else {
    print FH "set output figure_dir.\"\/$pure_name_dest.png\"\n";
}
# print FH "set yrange [-10:1000]\n";
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
foreach my $this_ip (keys %{ $ip_info{DEST_IP} }) {
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /128\.83/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /128\.83/ or $this_ip =~ /192\.168/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /192\.168/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.5/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.8/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.7/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.1/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /10.0.2.4/));
    next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /192.168.4.78/));
    # next if(scalar(keys %{ $ip_info{DEST_IP}{$this_ip}{TX_TIME} }) < $threshold or !($this_ip =~ /192.168.5.67/));

    print FH ", \\\n" if($tmp_cnt != 0);
    my $line_cnt = ($tmp_cnt % 6) + 1;
    $tmp_cnt ++;
    print FH "data_dir.\"\/$pure_name_dest.$this_ip.offset.txt\" using 3:6 with points ls $line_cnt title \"$this_ip\"";
 
    ## regression
    if(exists $ip_info{DEST_IP}{$this_ip}{ALPHA}) {
        $line_cnt = ($tmp_cnt % 6) + 1;
        $tmp_cnt ++;

        print FH ", \\\n";
        print FH $ip_info{DEST_IP}{$this_ip}{ALPHA}."*x - ".$ip_info{DEST_IP}{$this_ip}{BETA}." ls $line_cnt notitle";
    }
}
close FH;

my $cmd = "gnuplot $gnuplot_file";
`$cmd`;
$cmd = "rm $gnuplot_file";
`$cmd`;
