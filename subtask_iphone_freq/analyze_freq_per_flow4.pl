#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/10/15 @ Narus
##
## Analyze the frequence change per flow, use best fit line
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
##      perl analyze_freq_per_flow4.pl ../data/testbed/tcp_traces/text5/2013.10.14.iphone.tr2.iperf.pcap.txt 0 2 10 100 128 200 250 1000
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
my $gnuplot_boot_time_file = "plot_boot_time_per_flow4";

my $exp;
my @possible_freqs;

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
$file_name      = shift(@ARGV);
$exp            = shift(@ARGV) + 0;
@possible_freqs = @ARGV;
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


        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} = -1;
        my $min_bt_stdev = 0;
        my $best_freq = -1;
        foreach my $this_freq (@possible_freqs) {
            my @boot_time;
            foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })-1) {
                my $this_tx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$ind];
                my $this_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind];

                my $this_bt = $this_rx_time - $this_tx_time / $this_freq;
                push(@boot_time, $this_bt);
            }

            my $bt_stdev = MyUtil::stdev(\@boot_time);
            if($bt_stdev < $min_bt_stdev or $best_freq < 0) {
                $best_freq = $this_freq;
                $min_bt_stdev = $bt_stdev;
                @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} } = @boot_time;
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT} = min(@boot_time);
            }
        }

        print "$pure_name, $this_ip, $this_conn, $exp, best line, $best_freq, $min_bt_stdev\n";

    }  ## end for each conn
}  ## end for each ip



#####
## Generate freq output
print STDERR "start to generate boot time output..\n" if($DEBUG2);

foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {

        next if(!(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME}));
        open FH, ">$output_dir/$pure_name.$this_ip.conn$this_conn.best_fit$exp.freq_ts.txt" or die $!;
        # print FH join("\n", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} })."\n";
        foreach my $bt (@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} }) {
            print FH ($bt - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{MIN_BT})."\n";
        }
        close FH;

        #####
        ## gnuplot
        if($this_ip =~ /$PLOT_IP/) {
            print STDERR "  plot boot time: $pure_name.$this_ip.conn$this_conn ..\n" if($DEBUG2);
            my $cmd = "sed 's/DATA_DIR/output_freq/g; s/FIG_DIR/figures_freq/g; s/X_LABEL/time/g; s/Y_LABEL/boot time/g; s/FILE_NAME/$pure_name.$this_ip.conn$this_conn.best_fit$exp.freq_ts/g; s/FIG_NAME/$pure_name.$this_ip.conn$this_conn.best_fit$exp.bt/g; s/DEGREE/-45/g; s/X_RANGE_S//g; s/X_RANGE_E//g; s/Y_RANGE_S//g; s/Y_RANGE_E//g;' $gnuplot_boot_time_file.plot.mother > tmp.$gnuplot_boot_time_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;
            $cmd = "gnuplot tmp.$gnuplot_boot_time_file.$pure_name.$this_ip.conn$this_conn.plot";
            `$cmd`;
        }
    }
}
