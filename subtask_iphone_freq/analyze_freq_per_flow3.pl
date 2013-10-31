#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/10/15 @ Narus
##
## Analyze the frequence change per flow, using the packet x~y seconds ago as the base.
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
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
##      perl analyze_freq_per_flow3.pl ../data/testbed/tcp_traces/text5/2013.10.14.iphone.tr2.iperf.pcap.txt 0.8 0 1 10 11 12 13 14 15 16 17 18 19 20 30 40 50 60 70 80 90 100 200 300 400
##################################################

use strict;
use lib "../utils";

use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use MyUtil;

#####
## DEBUG
my $DEBUG0 = 0; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 0; ## print for debug

my $FIX_FREQ       = 1; ## fix frequency
my $PLOT_EPS       = 1; ## 1 to output eps; 0 to output png figure
my $PLOT_LOGX      = 0; ## 1 to plot log x; 0 otherwise
my $PLOT_TIMESTAMP = 0; ## 1 to plot received time v.s. Timestamp -- not very useful

my $FIX_DEST      = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
# my $FIX_DEST_ADDR = "192.168.5.67";
my $FIX_DEST_ADDR = "192.168.1.7|192.168.1.3|10.0.2.|192.168.0.|128.83.";
my $FIX_SRC       = 1; ## 1 to fix the TCP src
# my $FIX_SRC_ADDR  = "10.0.2.4";
# my $FIX_SRC_ADDR  = "128.83";
# my $FIX_SRC_ADDR  = "128.83.144.185";
# my $FIX_SRC_ADDR  = "28.222.97.95";
my $FIX_SRC_ADDR  = "192.168.1.7|192.168.1.3|10.0.2.|192.168.0.|128.83.";


## The IP to be plotted
# my $PLOT_IP       = "10.0.2.4"; 
# my $PLOT_IP       = "128.83";
# my $PLOT_IP       = "192.168";
# my $PLOT_IP       = "28.222.97.95";
my $PLOT_IP       = "192.168.1.7|192.168.1.3|10.0.2.|192.168.0.|128.83.";

my $THRESHOLD     = 100;



#####
## variables
my $output_dir = "./output_freq";
my $figure_dir = "./figures_freq";
my $gnuplot_freq_file      = "plot_freq_per_flow2";
my $gnuplot_boot_time_file = "plot_boot_time_per_flow";
my @ini_sec = (5);
my $exp = 0;

my $ewma_mean_freq  = -1;
my $ewma_median_freq  = -1;
my $ewma_alpha = 0;

my $file_name;
# my $target_ip;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}
                    ## {IP}{ip}{FREQS}[freqs]
                    ## {IP}{ip}{WINDOW_SIZE}{win size}{WIN_FREQS}[freqs]
                    ## {IP}{ip}{ALPHA}{alpha}{EWMA_FREQS}[freqs]



#####
## check input
# if(@ARGV != 3) {
#     print "wrong number of input\n";
#     exit;
# }
$file_name  = shift(@ARGV);
$ewma_alpha = shift(@ARGV) + 0;
$exp        = shift(@ARGV) + 0;
@ini_sec    = @ARGV;
my @tmp = split(/\//, $file_name);
my $pure_name = pop(@tmp);
print "input file = $file_name\n" if($DEBUG1);
print "input file name = $pure_name\n" if($DEBUG2);
print "exp $exp\n" if($DEBUG2);
print "  base=".join(", ", @ini_sec)."\n" if($DEBUG2);

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
    next if( (exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME}) and 
             ($tcp_ts_val == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME}[-1]) and 
             (($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME}[-1])
           );
    
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}     }, $seq);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME} }, $tcp_ts_val);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME} }, $time + $time_usec / 1000000);

}
close FH;

# die "there should be just one IP\n" if(scalar(keys %{ $ip_info{IP} }) > 1);

#####
## Calculate boot time
print STDERR "start to process data..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} } ) {

        if(scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SEQ} }) < $THRESHOLD) {
            delete $ip_info{IP}{$this_ip}{CONN}{$this_conn};
            next;
        }
        print "$this_ip - $this_conn (".scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })."), len=".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1]."-".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0]."=".($ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1]-$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0])."\n" if($DEBUG2);


        my @base_tx_time;
        my @base_rx_time;
        my @base_ind;
        foreach my $tmp (@ini_sec) {
            push(@base_tx_time, -1);
            push(@base_rx_time, -1);
            push(@base_ind, 0);
        }
        
        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} = -1;
        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })-1) {
            my $this_tx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$ind];
            my $this_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind];


            my @base_freq;
            foreach my $base (0 .. scalar(@ini_sec)-1) {
                my $ini_sec = $ini_sec[$base] + 0;
                print "base = $ini_sec\n" if($DEBUG1);

                my $base_tx_time = $base_tx_time[$base];
                my $base_rx_time = $base_rx_time[$base];
                my $base_ind     = $base_ind[$base];


                if($base_tx_time < 0) {
                    $base_tx_time[$base] = $this_tx_time;
                    $base_rx_time[$base] = $this_rx_time;
                    $base_ind[$base] = $ind;
                    
                    next;
                }

                print "  ".($this_rx_time - $base_rx_time)."\n" if($DEBUG1);
                if($this_rx_time - $base_rx_time < $ini_sec) {
                    next;
                }

                ## latest frequency
                my $tmp_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$base_ind+1];
                while($this_rx_time - $tmp_rx_time > $ini_sec) {
                    $base_ind ++;
                    $tmp_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$base_ind+1];
                }
                $base_tx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$base_ind];
                $base_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$base_ind];

                my $tmp_freq = ($this_tx_time - $base_tx_time) / ($this_rx_time - $base_rx_time);
                push(@base_freq, $tmp_freq);

                $base_tx_time[$base] = $base_tx_time;
                $base_rx_time[$base] = $base_rx_time;
                $base_ind[$base] = $base_ind;
            }
            next if(scalar(@base_freq) < 3);
            print " base freq size = ".scalar(@base_freq)."\n" if($DEBUG1);

            my $this_mean_freq = MyUtil::average(\@base_freq);
            my $this_median_freq = MyUtil::median(\@base_freq);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS} }, $this_mean_freq);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_FREQS} }, $this_median_freq);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME} }, $this_rx_time);
            
            my $this_mean_bt = $this_rx_time - $this_tx_time / $this_mean_freq;
            my $this_median_bt = $this_rx_time - $this_tx_time / $this_median_freq;
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_BT} }, $this_mean_bt);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_BT} }, $this_median_bt);

            if($this_mean_bt < $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} or 
               $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} < 0) {
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} = $this_mean_bt;
            }
            if($this_median_bt < $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} or 
               $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} < 0) {
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} = $this_median_bt;
            }

            ## ewma
            if($ewma_mean_freq == -1 or $ind < 1000) {
                $ewma_mean_freq = $this_mean_freq;
            }
            else {
                $ewma_mean_freq = $ewma_mean_freq * (1 - $ewma_alpha) + $this_mean_freq * $ewma_alpha;
            }
            my $ewma_mean_bt = $this_rx_time - $this_tx_time / $ewma_mean_freq;
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEAN_FREQS} }, $ewma_mean_freq);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEAN_BT} }, $ewma_mean_bt);
            if($ewma_mean_bt < $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} or 
               $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} < 0) {
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} = $ewma_mean_bt;
            }

            if($ewma_median_freq == -1 or $ind < 1000) {
                $ewma_median_freq = $this_median_freq;
            }
            else {
                $ewma_median_freq = $ewma_median_freq * (1 - $ewma_alpha) + $this_median_freq * $ewma_alpha;
            }
            my $ewma_median_bt = $this_rx_time - $this_tx_time / $ewma_median_freq;
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEDIAN_FREQS} }, $ewma_median_freq);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEDIAN_BT} }, $ewma_median_bt);
            if($ewma_median_bt < $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} or 
               $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} < 0) {
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} = $ewma_median_bt;
            }
        }  ## end for each packet
    }  ## end for each conn
}  ## end for each ip


#####
## Generate freq output
print STDERR "start to generate freq output..\n" if($DEBUG2);

foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {

        open FH, ">$output_dir/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.freq_ts.txt" or die $!;
        my $min_freq = 1000;
        my $max_freq = 0;
        next if(!(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS}));
        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS} })-1) {
            print FH ($ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME}[$ind]-$ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME}[0]).", ";

            ## mean:
            ## latest frequency
            print FH $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS}[$ind].", ";
            if($ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS}[$ind] < $min_freq) {
                $min_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS}[$ind];
            }
            if($ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS}[$ind] > $max_freq) {
                $max_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_FREQS}[$ind];
            }

            ## boot time
            print FH ($ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_BT}[$ind] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT}).", ";

            ## ewma frequency
            print FH $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEAN_FREQS}[$ind].", ";

            ## ewma boot time
            print FH ($ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEAN_BT}[$ind] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT}).", ";


            ## median:
            ## latest frequency
            print FH $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_FREQS}[$ind].", ";
            if($ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_FREQS}[$ind] < $min_freq) {
                $min_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_FREQS}[$ind];
            }
            if($ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_FREQS}[$ind] > $max_freq) {
                $max_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_FREQS}[$ind];
            }

            ## boot time
            print FH ($ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_BT}[$ind] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT}).", ";

            ## ewma frequency
            print FH $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEDIAN_FREQS}[$ind].", ";

            ## ewma boot time
            print FH ($ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEDIAN_BT}[$ind] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT})."\n";
        }
        close FH;


        #####
        ## gnuplot
        if($this_ip =~ /$PLOT_IP/) {
            ## mean
            print STDERR "  plot freq: $pure_name.$this_ip.conn.$this_conn ..\n" if($DEBUG2);
            my $cmd = "sed 's/DATA_DIR/output_freq/g; s/FIG_DIR/figures_freq/g; s/X_LABEL/time/g; s/Y_LABEL/frequency/g; s/FILE_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.freq_ts/g; s/FIG_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.mean_freq_ts/g; s/DEGREE/-45/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/".max(0, $min_freq-100)."/g; s/Y_RANGE_E/".min(1000, $max_freq+100)."/g; s/DATA_IND_1/2/g; s/DATA_IND_2/4/g;' $gnuplot_freq_file.plot.mother > tmp.$gnuplot_freq_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;
            $cmd = "gnuplot tmp.$gnuplot_freq_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;


            print STDERR "  plot boot time: $pure_name.$this_ip.conn$this_conn ..\n" if($DEBUG2);
            my $cmd = "sed 's/DATA_DIR/output_freq/g; s/FIG_DIR/figures_freq/g; s/X_LABEL/time/g; s/Y_LABEL/boot time/g; s/FILE_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.freq_ts/g; s/FIG_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.mean_bt/g; s/DEGREE/-45/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DATA_IND_1/3/g; s/DATA_IND_2/5/g;' $gnuplot_boot_time_file.plot.mother > tmp.$gnuplot_boot_time_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;
            $cmd = "gnuplot tmp.$gnuplot_boot_time_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;

            ## median
            print STDERR "  plot freq: $pure_name.$this_ip.conn.$this_conn ..\n" if($DEBUG2);
            my $cmd = "sed 's/DATA_DIR/output_freq/g; s/FIG_DIR/figures_freq/g; s/X_LABEL/time/g; s/Y_LABEL/frequency/g; s/FILE_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.freq_ts/g; s/FIG_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.median_freq_ts/g; s/DEGREE/-45/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S/".max(0, $min_freq-100)."/g; s/Y_RANGE_E/".min(1000, $max_freq+100)."/g; s/DATA_IND_1/6/g; s/DATA_IND_2/8/g;' $gnuplot_freq_file.plot.mother > tmp.$gnuplot_freq_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;
            $cmd = "gnuplot tmp.$gnuplot_freq_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;


            print STDERR "  plot boot time: $pure_name.$this_ip.conn$this_conn ..\n" if($DEBUG2);
            my $cmd = "sed 's/DATA_DIR/output_freq/g; s/FIG_DIR/figures_freq/g; s/X_LABEL/time/g; s/Y_LABEL/boot time/g; s/FILE_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.freq_ts/g; s/FIG_NAME/$pure_name.$this_ip.conn$this_conn.multi_ini$exp.median_bt/g; s/DEGREE/-45/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g; s/DATA_IND_1/7/g; s/DATA_IND_2/9/g;' $gnuplot_boot_time_file.plot.mother > tmp.$gnuplot_boot_time_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;
            $cmd = "gnuplot tmp.$gnuplot_boot_time_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;
        }

        print "$pure_name, $this_ip, $this_conn, $exp, $ewma_alpha, muli-init mean, ".MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEAN_BT} }).", mean ewma, ".MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEAN_BT} }).", muli-init median, ".MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MEDIAN_BT} }).", median ewma, ".MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{EWMA_MEDIAN_BT} })."\n";
    }  ## end of the flow
}

