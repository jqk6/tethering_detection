#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/30 @ Narus
##
## Analyze the following things:
## a) See how long does the frequence per flow take to become stable.
## b) How long are the flows (in seconds)
## c) How many packets per flow
## d) How much traffic per flow
## e) How many flows per IP
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
##     a) <input file name>.flow_size.txt
##        format
##        <length of flow (s)> <# packets of flows> <traffic of flows>
##     b) <input file name>.num_flows_per_ip.txt
##        format
##        <# of flows of an IP>
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
##      perl time_to_stable_boottime_per_flow.pl /data/ychen/sprint/text5/omni.out.49.eth.pcap.txt
##################################################

use strict;
use List::Util qw(sum);
use MyUtil;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $FIX_FREQ       = 1; ## fix frequency
my $PLOT_EPS       = 1; ## 1 to output eps; 0 to output png figure
my $PLOT_LOGX      = 0; ## 1 to plot log x; 0 otherwise
my $PLOT_TIMESTAMP = 0; ## 1 to plot received time v.s. Timestamp -- not very useful

my $FIX_DEST      = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DEST_ADDR = "192.168.5.67";
my $FIX_SRC       = 0; ## 1 to fix the TCP src
# my $FIX_SRC_ADDR  = "10.0.2.4";
# my $FIX_SRC_ADDR  = "128.83";
# my $FIX_SRC_ADDR  = "128.83.144.185";
my $FIX_SRC_ADDR  = "28.222.97.95";

## The IP to be plotted
# my $PLOT_IP       = "10.0.2.4"; 
# my $PLOT_IP       = "128.83";
# my $PLOT_IP       = "192.168";
my $PLOT_IP       = "28.222.97.95";

my $THRESHOLD     = 4;
my $STABLE_THRESHOLD = 1;


#####
## variables
my $output_dir = "./output";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_freq.plot";

my $file_name;
# my $target_ip;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}
                    ## {IP}{ip}{FREQS}[freqs]
                    ## {IP}{ip}{WINDOW_SIZE}{win size}{WIN_FREQS}[freqs]
                    ## {IP}{ip}{ALPHA}{alpha}{EWMA_FREQS}[freqs]
                    ## statistics
                    ## {FLOW_PER_IP}[# of flows per IP]
                    ## {FLOW_LENGTH}[length of flows]
                    ## {FLOW_TRAFFIC}[amoung of traffic of flows]
                    ## {FLOW_PACKET}[# of packets of flows]


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


    next if($FIX_SRC  and (!($src =~ /$FIX_SRC_ADDR/ )));
    next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    ## check if it's a reordering / retransmission
    next if(exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ} and $seq < $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}[-1]);
    ## check if it's a duplicate
    next if(exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME} and 
            $tcp_ts_val == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME}[-1] and 
            ($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME}[-1] and 
            $seq == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}[-1]);

    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}     }, $seq);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{PKT_SIZE}}, $len);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME} }, $tcp_ts_val);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME} }, $time + $time_usec / 1000000);

}
close FH;

# die "there should be just one IP\n" if(scalar(keys %{ $ip_info{IP} }) > 1);

#####
## Calculate frequency
print STDERR "start to process data..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    ## e) number of flow of this IP
    my $this_num_flows = scalar (keys %{ $ip_info{IP}{$this_ip}{CONN} } );
    push(@{ $ip_info{FLOW_PER_IP} }, $this_num_flows);

    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} } ) {

        ## b) How long are the flows (in seconds)
        ## c) How many packets per flow
        ## d) How much traffic per flow
        my $this_length  = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1] - 
                           $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0];
        my $this_num_pkt = scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} });
        my $this_traffic = sum(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{PKT_SIZE} });
        push(@{ $ip_info{FLOW_LENGTH} }, $this_length);
        push(@{ $ip_info{FLOW_PACKET} }, $this_num_pkt);
        push(@{ $ip_info{FLOW_TRAFFIC} }, $this_traffic);


        print "$this_ip - $this_conn (".scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })."), len=".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1]."-".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0]."=".$this_length."\n" if($DEBUG1);


        my $first_tx_time = -1;
        my $first_rx_time = -1;
        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })-1) {

            my $this_tx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$ind];
            my $this_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind];

            if($first_tx_time < 0) {
                $first_tx_time = $this_tx_time;
                $first_rx_time = $this_rx_time;
                
                next;
            }

            ## latest frequency
            next if($DEBUG0 and ($this_rx_time == $first_rx_time or $this_tx_time == $first_tx_time));
            my $this_freq = ($this_tx_time - $first_tx_time) / ($this_rx_time - $first_rx_time);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} }, $this_freq);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME} }, $this_rx_time);
            

        }  ## end for each packet
    }  ## end for each conn
}  ## end for each ip


#####
## how long to become stable
my $num_flow_become_stable = 0;
my $num_flow = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} } ) {
        next if(!exists($ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}));

        my $first_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0];
        my $stable_time = -1;

        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} })-5) {
            my $this_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME}[$ind];
            my $this_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}[$ind];
            my @tmp1 = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} };
            my @tmp2 = @tmp1[$ind .. scalar(@tmp1) - 1];
            my $this_stdev = MyUtil::stdev(\@tmp2);
            print "$this_stdev ($this_freq), " if($DEBUG1);
            if($this_stdev < $STABLE_THRESHOLD) {
                $stable_time = $this_rx_time - $first_rx_time;

                if($DEBUG2) {
                    print "\n------------------------------------\n";
                    foreach my $ind2 (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} })-1) {
                        my $tmp_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME}[$ind2];
                        my $tmp_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}[$ind2];
                        print "$tmp_freq, $tmp_time\n";
                    }
                    print "stable time = $stable_time\n";
                }

                last;
            }
        }
        print "\n" if($DEBUG1);

        $num_flow ++;
        if($stable_time > 0) {
            ## become stable
            $num_flow_become_stable ++;
            push(@{ $ip_info{STABLE_TIME} }, $stable_time);
        }
    }
}


#####
## Generate output
print STDERR "start to generate output..\n" if($DEBUG2);

## a) How long does a flow to take for its frequency to become stable
open FH, ">$output_dir/$pure_name.flow_stable_time.txt" or die $!;
print "$num_flow_become_stable / $num_flow\n";
print FH "# $num_flow_become_stable / $num_flow\n";
foreach my $this_stable_time (@{ $ip_info{STABLE_TIME} }) {
    print FH $this_stable_time."\n";
}    
close FH;

## b) How long are the flows (in seconds)
## c) How many packets per flow
## d) How much traffic per flow
open FH, ">$output_dir/$pure_name.flow_size.txt" or die $!;
foreach my $ind (0 .. @{ $ip_info{FLOW_LENGTH} }-1) {
    my $this_length = $ip_info{FLOW_LENGTH}[$ind];
    my $this_num_pkt = $ip_info{FLOW_PACKET}[$ind];
    my $this_traffic = $ip_info{FLOW_TRAFFIC}[$ind];
    print FH "$this_length, $this_num_pkt, $this_traffic\n";
}
close FH;

## e) How many flows per IP
open FH, ">$output_dir/$pure_name.num_flows_per_ip.txt" or die $!;
foreach my $this_num_flows (@{ $ip_info{FLOW_PER_IP} }) {
    print FH "$this_num_flows\n";
}
close FH;



