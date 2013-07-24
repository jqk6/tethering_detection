#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/24 @ Narus
##
## Detect tethering by calculating the boot time.
##
## - input: 
##     a) parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##     b) freq_est_method: the method to estimate frequency
##        FREQ_METHOD_WIN  (1): averag frequency of a window
##        FREQ_METHOD_EWMA (2): EWMA based estimation
##        FREQ_METHOD_LAST (3): use the last calculated frequency
##     c) parameter: the parameter for the frequency estimation method
##          i.e. "window size" for FREQ_METHOD_WIN, "alpha" for FREQ_METHOD_EWMA
##     d) THRESHOLD_EST_RX_DIFF: 
##          if estimated_rx_time - actual_rx_time > threshold, then it's from another device.
##     e) OUT_RANGE_NUM:
##          if number of packet that has out range est rx time, then it's from another device.
##
## - output
##
##
##  e.g.
##      perl detect_tethering_boot_time.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt 2 0.9 5 2
##################################################

use strict;

use MyUtil;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug


#####
## Constant
my $FREQ_METHOD_WIN       = 1;  ## averag frequency of a window
my $FREQ_METHOD_EWMA      = 2;  ## EWMA based estimation
my $FREQ_METHOD_LAST      = 3;  ## use the last calculated frequency

my $INITIALIZATION_PERIOD = 1;  ## the initialization period, in seconds
my $THRESHOLD_EST_RX_DIFF ;     ## if estimated_rx_time - actual_rx_time > threshold, then it's from another device.
my $OUT_RANGE_NUM         ;     ## if number of packet that has out range est rx time, then it's from another device

my $FIX_SRC               = 0; ## 1 to fix the TCP src
my $FIX_SRC_ADDR          = "^28.";
# my $FIX_SRC_ADDR          = "128.83";
# my $FIX_SRC_ADDR        = "10.0.2.4";


#####
## variables
my $output_freq_dir   = "./output_boot_time_freq";
my $output_tether_dir = "./tethered_clients";

my $file_name;
my $file_id = -1;
my $freq_est_method;
my $freq_est_param;
# my $target_ip;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}
                    ## {IP}{ip}{FREQS}[freqs]
                    ## {IP}{ip}{EST_FREQS}[freqs]
                    ## {IP}{ip}{OUT_RANGE_NUM}{num pkt}


#####
## check input
if(@ARGV != 5) {
    print "wrong number of input\n";
    exit;
}
if($ARGV[0] =~ /^\d+$/) {
    $file_id = $ARGV[0];
    $file_name = "/data/ychen/sprint/text5/omni.out.$file_id.eth.pcap.txt";
}
else {
    $file_name = $ARGV[0];
}
my @tmp = split(/\//, $file_name);
my $pure_name = pop(@tmp);
print "input file = $file_name\n" if($DEBUG2);
print "input file name = $pure_name\n" if($DEBUG2);

$freq_est_method = $ARGV[1] + 0;
$freq_est_param  = $ARGV[2] + 0;
## if estimated_rx_time - actual_rx_time > threshold, then it's from another device.
$THRESHOLD_EST_RX_DIFF = $ARGV[3] + 0;
## if number of packet that has out range est rx time, then it's from another device
$OUT_RANGE_NUM         = $ARGV[4] + 0;


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
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    $ip_info{IP}{$src}{TX_TIME}{$tcp_ts_val}{RX_TIME}{$time + $time_usec / 1000000} = 1;
}
close FH;

# die "there should be just one IP\n" if(scalar(keys %{ $ip_info{IP} }) > 1);


#####
## Calculate boot time
print STDERR "start to process data..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    print "$this_ip (".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }).")\n" if($DEBUG1);


    my $first_tx_time = -1;
    my $first_rx_time = -1;
    my $freq = -1;
    foreach my $this_tx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{TX_TIME} })) {
        foreach my $this_rx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{TX_TIME}{$this_tx_time}{RX_TIME} })) {
            print "TX: $this_tx_time, RX: $this_rx_time\n" if($DEBUG1);


            ## first packet of this IP
            if($first_tx_time < 0) {
                $first_tx_time = $this_tx_time;
                $first_rx_time = $this_rx_time;
                
                next;
            }

            ## initialization period
            if($this_rx_time - $first_rx_time < $INITIALIZATION_PERIOD) {
                ## do nothing or update frequency?
                
                next;
            }

            ## get the first freq estimation
            if($freq == -1 && $this_tx_time != $first_tx_time) {
                $freq = ($this_tx_time - $first_tx_time) / ($this_rx_time - $first_rx_time);
                push(@{ $ip_info{IP}{$this_ip}{FREQS} }, $freq);
                push(@{ $ip_info{IP}{$this_ip}{EST_FREQS} }, $freq);
                die "  !!freq shouldn't be negative: $freq\n" if($DEBUG0 and $freq <= 0);

                next;
            }
            

            my $estimated_rx_time = $first_rx_time + ($this_tx_time - $first_tx_time) / $freq;
            my $this_err = abs($estimated_rx_time - $this_rx_time);
            push(@{ $ip_info{IP}{$this_ip}{ERRS} }, $this_err);
            ## check if it's from another device
            if($this_err > $THRESHOLD_EST_RX_DIFF) {
                $ip_info{IP}{$this_ip}{OUT_RANGE_NUM} ++;
                next;
            }

            ## it's from the same device, update the frequency
            my $new_freq = ($this_tx_time - $first_tx_time) / ($this_rx_time - $first_rx_time);
            next if($new_freq == 0);
            push(@{ $ip_info{IP}{$this_ip}{FREQS} }, $new_freq);
            if($freq_est_method == $FREQ_METHOD_WIN) {
                ## window based method
                # while(scalar @{ $ip_info{IP}{$this_ip}{FREQS} } > $freq_est_param) {
                #     shift @{ $ip_info{IP}{$this_ip}{FREQS} };
                # }
                # push(@{ $ip_info{IP}{$this_ip}{FREQS} }, $new_freq);
                # $freq = MyUtil::average(\@{ $ip_info{IP}{$this_ip}{FREQS} });
                if(scalar @{ $ip_info{IP}{$this_ip}{FREQS} } < $freq_est_param) {
                    $freq = MyUtil::average(\@{ $ip_info{IP}{$this_ip}{FREQS} });
                }
                else {
                    my @this_win = @{ $ip_info{IP}{$this_ip}{FREQS} }[-$freq_est_param .. -1];
                    $freq = MyUtil::average(\@this_win);
                }
            }
            elsif($freq_est_method == $FREQ_METHOD_EWMA) {
                $freq = $freq_est_param * $new_freq + (1 - $freq_est_param) * $freq;
            }
            elsif($freq_est_method == $FREQ_METHOD_LAST) {
                $freq = $new_freq;
            }
            die "  !!freq shouldn't be negative: $freq\n" if($DEBUG0 and $freq <= 0);
            push(@{ $ip_info{IP}{$this_ip}{EST_FREQS} }, $freq);
        }
    }  ## end for each packet
}  ## end for each IP


#####
## Generate output
print STDERR "start to output freq timeseries and tethered IPs..\n" if($DEBUG2);

open FH, ">$output_freq_dir/$pure_name.freq_ts.method_$freq_est_method.$freq_est_param.DIFF_$THRESHOLD_EST_RX_DIFF.NUM_$OUT_RANGE_NUM.txt" or die $!;
open FH_ERR, ">$output_freq_dir/$pure_name.errs.method_$freq_est_method.$freq_est_param.DIFF_$THRESHOLD_EST_RX_DIFF.NUM_$OUT_RANGE_NUM.txt" or die $!;
my $tmp = $pure_name;
if($file_id >= 0) {
    $tmp = $file_id;
}
open FH_TETHER, ">$output_tether_dir/boot_time.method_$freq_est_method.$freq_est_param.DIFF_$THRESHOLD_EST_RX_DIFF.NUM_$OUT_RANGE_NUM.$tmp.txt" or die $!;
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    next if(!(defined $ip_info{IP}{$this_ip}{FREQS}));

    ## frequency
    my $str_freq1 = "$this_ip, ";
    my $str_freq2 = "$this_ip, ";
    
    foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{FREQS} })-1) {
        $str_freq1 .= ($ip_info{IP}{$this_ip}{FREQS}[$ind].", ");
        $str_freq2 .= ($ip_info{IP}{$this_ip}{EST_FREQS}[$ind].", ");
    }
    print FH $str_freq1."\n";
    print FH $str_freq2."\n";


    ## errors
    print FH_ERR "$this_ip, ";
    foreach my $this_err (@{ $ip_info{IP}{$this_ip}{ERRS} }) {
        print FH_ERR "$this_err, ";
    }
    print FH_ERR "\n";


    ## tethered IPs
    if($ip_info{IP}{$this_ip}{OUT_RANGE_NUM} > $OUT_RANGE_NUM) {
        print FH_TETHER "$this_ip\n";
        print "$this_ip: ".$ip_info{IP}{$this_ip}{OUT_RANGE_NUM}."/".scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }).", err=".MyUtil::average(\@{ $ip_info{IP}{$this_ip}{ERRS} })."\n" if($DEBUG1);
    }
}
close FH;
close FH_ERR;
close FH_TETHER;



