#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/30 @ Narus
##
## Analyze the frequence change per flow over packets .
##   a) latest frequency
##   b) avg frequency
##   c) avg frequency in a time window
##   d) EWMA
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
##      perl analyze_freq.pl ~/testbed/tcp_traces/text5/2013.07.08.ut.4machines.pcap.txt
##################################################

use strict;

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
my $FIX_SRC       = 1; ## 1 to fix the TCP src
# my $FIX_SRC_ADDR  = "10.0.2.4";
# my $FIX_SRC_ADDR  = "128.83";
# my $FIX_SRC_ADDR  = "128.83.144.185";
my $FIX_SRC_ADDR  = "28.222.97.95";

## The IP to be plotted
# my $PLOT_IP       = "10.0.2.4"; 
# my $PLOT_IP       = "128.83";
# my $PLOT_IP       = "192.168";
my $PLOT_IP       = "28.222.97.95";

my $THRESHOLD     = 6;



#####
## variables
my $output_dir = "./output_freq";
my $figure_dir = "./figures_freq";
my $gnuplot_file = "plot_freq.plot";

my $file_name;
# my $target_ip;

my %ip_info;        ## IP
                    ## {IP}{ip}{TX_TIME}{sending time}{RX_TIME}{receiving time}
                    ## {IP}{ip}{FREQS}[freqs]
                    ## {IP}{ip}{WINDOW_SIZE}{win size}{WIN_FREQS}[freqs]
                    ## {IP}{ip}{ALPHA}{alpha}{EWMA_FREQS}[freqs]



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
            if($DEBUG0 and ($this_rx_time == $first_rx_time or $this_tx_time == $first_tx_time)) {
                die "first ($first_rx_time, $first_tx_time), latest ($this_rx_time, $this_tx_time)\n" if($DEBUG2);
                next;
            }
            my $this_freq = ($this_tx_time - $first_tx_time) / ($this_rx_time - $first_rx_time);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} }, $this_freq);

        }  ## end for each packet
    }  ## end for each conn
}  ## end for each ip


#####
## Generate output
print STDERR "start to generate output..\n" if($DEBUG2);

foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {

        open FH, ">$output_dir/$pure_name.$this_ip.conn.$this_conn.freq_ts.txt" or die $!;
        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} })-1) {
            print FH $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$ind].", ";

            ## latest frequency
            print FH $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}[$ind]."\n";
        }
        close FH;
    }
}


#####
## plot
# print STDERR "start to plot..\n" if($DEBUG2);
# foreach my $this_ip (keys %{ $ip_info{IP} }) {
#     # next if(scalar(keys %{ $ip_info{IP}{$this_ip}{TX_TIME} }) < $THRESHOLD or !($this_ip =~ /$PLOT_IP/));


#     open FH, ">$gnuplot_file" or dir $!;
#     print FH "reset\n";
#     if($PLOT_EPS) {
#         print FH "set terminal postscript enhanced\n";
#     }
#     else {
#         print FH "set term pngcairo\n";
#     }
#     print FH "set size ratio 0.7\n";
#     print FH "figure_dir = \"$figure_dir\"\n";
#     print FH "data_dir = \"$output_dir\"\n";
#     # print FH "set yrange [-0.01:0.01]\n";
#     print FH "set xlabel \"Timestamp\"\n";
#     print FH "set ylabel \"frequency (Hz)\"\n";
#     if($PLOT_LOGX) {
#         print FH "set logscale x\n";
#     }
#     print FH "set key Left under reverse nobox spacing 2\n";
#     print FH "set xtics rotate by 315\n";

#     # print FH "set style line 1 lc rgb \"#FF0000\" ps 2 pt 3 lt 1 lw 3\n";
#     print FH "set style line 1 lc rgb \"#FF0000\" ps 1 lw 3\n";
#     print FH "set style line 2 lc rgb \"#0000FF\" ps 1 lw 3\n";
#     print FH "set style line 3 lc rgb \"orange\" ps 1 lw 3\n";
#     print FH "set style line 4 lc rgb \"green\" ps 1 lw 3\n";
#     print FH "set style line 5 lc rgb \"yellow\" ps 1 lw 3\n";
#     print FH "set style line 6 lc rgb \"black\" ps 1 lw 3\n";
#     print FH "set style line 7 lc rgb \"#FF0000\" ps 1 lw 3\n";
#     print FH "set style line 8 lc rgb \"#0000FF\" ps 1 lw 3\n";
#     print FH "set style line 9 lc rgb \"orange\" ps 1 lw 3\n";
#     print FH "set style line 10 lc rgb \"green\" ps 1 lw 3\n";
#     print FH "set style line 11 lc rgb \"yellow\" ps 1 lw 3\n";
#     print FH "set style line 12 lc rgb \"black\" ps 1 lw 3\n";
    
    
#     #############################################
#     print FH "\n################################\n";
#     if($PLOT_EPS) {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.freq.freq_ts.eps\"\n";
#     }
#     else {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.freq.freq_ts.png\"\n";
#     }
#     print FH "plot ";
#     my $cnt = 0;
#     my $local_cnt = 0;
#     ## a) latest frequency
#     my $line_cnt = ($local_cnt % 12) + 1;
#     $cnt = 2;
#     $local_cnt ++;
#     print FH "data_dir.\"\/$pure_name.$this_ip.freq_ts.txt\" using 1:$cnt with points ls $line_cnt title \"freq\"";
    
    
#     ## b) avg frequency
#     print FH ", \\\n";
#     $line_cnt = ($local_cnt % 12) + 1;
#     $cnt ++;
#     $local_cnt ++;
#     print FH "data_dir.\"\/$pure_name.$this_ip.freq_ts.txt\" using 1:$cnt with points ls $line_cnt title \"avg\"";

    

#     #############################################
#     print FH "\n################################\n";
#     if($PLOT_EPS) {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.win.freq_ts.eps\"\n";
#     }
#     else {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.win.freq_ts.png\"\n";
#     }
#     print FH "plot ";
#     $local_cnt = 0;
#     ## c) avg frequency in a time window
#     foreach my $this_win_size (@WINDOW_SIZE) {
#         print FH ", \\\n" if($local_cnt != 0);
#         $line_cnt = ($local_cnt % 12) + 1;
#         $cnt ++;
#         $local_cnt ++;
#         print FH "data_dir.\"\/$pure_name.$this_ip.freq_ts.txt\" using 1:$cnt with points ls $line_cnt title \"win size=$this_win_size\"";
#     }


#     #############################################
#     print FH "\n################################\n";
#     if($PLOT_EPS) {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.ewma.freq_ts.eps\"\n";
#     }
#     else {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.ewma.freq_ts.png\"\n";
#     }
#     print FH "plot ";
#     $local_cnt = 0;
#     ## d) EWMA
#     foreach my $this_alpha (@ALPHA) {
#         print FH ", \\\n" if($local_cnt != 0);
#         $line_cnt = ($local_cnt % 12) + 1;
#         $cnt ++;
#         $local_cnt ++;
#         print FH "data_dir.\"\/$pure_name.$this_ip.freq_ts.txt\" using 1:$cnt with points ls $line_cnt title \"EWMA alpha=$this_alpha\"";
#     }


#     ##########################################################################
#     ## timestamp timeseries
#     ##########################################################################
#     if($PLOT_TIMESTAMP) {

#         print FH "\n\n\n########################################\n";
#         print FH "reset\n";
#         if($PLOT_EPS) {
#             print FH "set terminal postscript enhanced\n";
#         }
#         else {
#             print FH "set term pngcairo\n";
#         }
#         print FH "set size ratio 0.7\n";
#         print FH "figure_dir = \"$figure_dir\"\n";
#         print FH "data_dir = \"$output_dir\"\n";
#         # print FH "set yrange [-0.01:0.01]\n";
#         print FH "set xlabel \"TIMESTAMP\"\n";
#         print FH "set ylabel \"received time\"\n";
#         if($PLOT_LOGX) {
#             print FH "set logscale x\n";
#         }
#         print FH "set key Left under reverse nobox spacing 2\n";
#         print FH "set xtics rotate by 315\n";

#         # print FH "set style line 1 lc rgb \"#FF0000\" ps 2 pt 3 lt 1 lw 3\n";
#         print FH "set style line 1 lc rgb \"#FF0000\" ps 1 lw 3\n";
#         print FH "set style line 2 lc rgb \"#0000FF\" ps 1 lw 3\n";
#         print FH "set style line 3 lc rgb \"orange\" ps 1 lw 3\n";
#         print FH "set style line 4 lc rgb \"green\" ps 1 lw 3\n";
#         print FH "set style line 5 lc rgb \"yellow\" ps 1 lw 3\n";
#         print FH "set style line 6 lc rgb \"black\" ps 1 lw 3\n";
#         print FH "set style line 7 lc rgb \"#FF0000\" ps 1 lw 3\n";
#         print FH "set style line 8 lc rgb \"#0000FF\" ps 1 lw 3\n";
#         print FH "set style line 9 lc rgb \"orange\" ps 1 lw 3\n";
#         print FH "set style line 10 lc rgb \"green\" ps 1 lw 3\n";
#         print FH "set style line 11 lc rgb \"yellow\" ps 1 lw 3\n";
#         print FH "set style line 12 lc rgb \"black\" ps 1 lw 3\n";
        
        
#         #############################################
#         print FH "\n################################\n";
#         if($PLOT_EPS) {
#             print FH "set output figure_dir.\"\/$pure_name.$this_ip.freq.timestamp_ts.eps\"\n";
#         }
#         else {
#             print FH "set output figure_dir.\"\/$pure_name.$this_ip.freq.timestamp_ts.png\"\n";
#         }
#         $local_cnt = 0;
#         $line_cnt = ($local_cnt % 12) + 1;
#         $cnt = 2;
#         $local_cnt ++;
#         print FH "plot data_dir.\"\/$pure_name.$this_ip.timestamp_ts.txt\" using 1:2  with points ls $line_cnt title \"freq\"";
        
#         ## a) latest frequency
#         print FH ", \\\n" if($local_cnt != 0);
#         $line_cnt = ($local_cnt % 12) + 1;
#         $cnt ++;
#         $local_cnt ++;
#         print FH "data_dir.\"\/$pure_name.$this_ip.timestamp_ts.txt\" using 1:$cnt  with points ls $line_cnt title \"freq\"";
        
        
#         ## b) avg frequency
#         print FH ", \\\n" if($local_cnt != 0);
#         $line_cnt = ($local_cnt % 12) + 1;
#         $cnt ++;
#         $local_cnt ++;
#         print FH "data_dir.\"\/$pure_name.$this_ip.timestamp_ts.txt\" using 1:$cnt with points ls $line_cnt title \"avg\"";

        

#         #############################################
#         print FH "\n################################\n";
#         if($PLOT_EPS) {
#             print FH "set output figure_dir.\"\/$pure_name.$this_ip.win.timestamp_ts.eps\"\n";
#         }
#         else {
#             print FH "set output figure_dir.\"\/$pure_name.$this_ip.win.timestamp_ts.png\"\n";
#         }
#         $local_cnt = 0;
#         $line_cnt = ($local_cnt % 12) + 1;
#         $local_cnt ++;
#         print FH "plot data_dir.\"\/$pure_name.$this_ip.timestamp_ts.txt\" using 1:2 with points ls $line_cnt title \"freq\"";
#         ## c) avg frequency in a time window
#         foreach my $this_win_size (@WINDOW_SIZE) {
#             print FH ", \\\n" if($local_cnt != 0);
#             $line_cnt = ($local_cnt % 12) + 1;
#             $cnt ++;
#             $local_cnt ++;
#             print FH "data_dir.\"\/$pure_name.$this_ip.timestamp_ts.txt\" using 1:$cnt with points ls $line_cnt title \"win size=$this_win_size\"";
#         }


#         #############################################
#         print FH "\n################################\n";
#         if($PLOT_EPS) {
#             print FH "set output figure_dir.\"\/$pure_name.$this_ip.ewma.timestamp_ts.eps\"\n";
#         }
#         else {
#             print FH "set output figure_dir.\"\/$pure_name.$this_ip.ewma.timestamp_ts.png\"\n";
#         }
#         $local_cnt = 0;
#         $line_cnt = ($local_cnt % 12) + 1;
#         $local_cnt ++;
#         print FH "plot data_dir.\"\/$pure_name.$this_ip.timestamp_ts.txt\" using 1:2 with points ls $line_cnt title \"freq\"";
#         ## d) EWMA
#         foreach my $this_alpha (@ALPHA) {
#             print FH ", \\\n" if($local_cnt != 0);
#             $line_cnt = ($local_cnt % 12) + 1;
#             $cnt ++;
#             $local_cnt ++;
#             print FH "data_dir.\"\/$pure_name.$this_ip.timestamp_ts.txt\" using 1:$cnt with points ls $line_cnt title \"EWMA alpha=$this_alpha\"";
#         }

#     }   ## end if PLOT_TIMESTAMP



#     ##########################################################################
#     ## error timeseries
#     ##########################################################################
#     print FH "\n\n\n########################################\n";
#     print FH "reset\n";
#     if($PLOT_EPS) {
#         print FH "set terminal postscript enhanced\n";
#     }
#     else {
#         print FH "set term pngcairo\n";
#     }
#     print FH "set size ratio 0.7\n";
#     print FH "figure_dir = \"$figure_dir\"\n";
#     print FH "data_dir = \"$output_dir\"\n";
#     # print FH "set yrange [-0.01:0.01]\n";
#     print FH "set xlabel \"TIMESTAMP\"\n";
#     print FH "set ylabel \"error of estimated time (s)\"\n";
#     if($PLOT_LOGX) {
#         print FH "set logscale x\n";
#     }
#     print FH "set key Left under reverse nobox spacing 2\n";
#     print FH "set xtics rotate by 315\n";

#     # print FH "set style line 1 lc rgb \"#FF0000\" ps 2 pt 3 lt 1 lw 3\n";
#     print FH "set style line 1 lc rgb \"#FF0000\" ps 1 lw 3\n";
#     print FH "set style line 2 lc rgb \"#0000FF\" ps 1 lw 3\n";
#     print FH "set style line 3 lc rgb \"orange\" ps 1 lw 3\n";
#     print FH "set style line 4 lc rgb \"green\" ps 1 lw 3\n";
#     print FH "set style line 5 lc rgb \"yellow\" ps 1 lw 3\n";
#     print FH "set style line 6 lc rgb \"black\" ps 1 lw 3\n";
#     print FH "set style line 7 lc rgb \"#FF0000\" ps 1 lw 3\n";
#     print FH "set style line 8 lc rgb \"#0000FF\" ps 1 lw 3\n";
#     print FH "set style line 9 lc rgb \"orange\" ps 1 lw 3\n";
#     print FH "set style line 10 lc rgb \"green\" ps 1 lw 3\n";
#     print FH "set style line 11 lc rgb \"yellow\" ps 1 lw 3\n";
#     print FH "set style line 12 lc rgb \"black\" ps 1 lw 3\n";
    
    
#     #############################################
#     print FH "\n################################\n";
#     if($PLOT_EPS) {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.freq.err_ts.eps\"\n";
#     }
#     else {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.freq.err_ts.png\"\n";
#     }
#     print FH "plot ";
    
#     ## a) latest frequency
#     $local_cnt = 0;
#     print FH ", \\\n" if($local_cnt != 0);
#     $line_cnt = ($local_cnt % 12) + 1;
#     $cnt = 2;
#     # $local_cnt ++;
#     # print FH "data_dir.\"\/$pure_name.$this_ip.err_ts.txt\" using 1:$cnt  with points ls $line_cnt title \"freq\"";
    
    
#     ## b) avg frequency
#     print FH ", \\\n" if($local_cnt != 0);
#     $line_cnt = ($local_cnt % 12) + 1;
#     $cnt ++;
#     $local_cnt ++;
#     print FH "data_dir.\"\/$pure_name.$this_ip.err_ts.txt\" using 1:$cnt with points ls $line_cnt title \"avg\"";

    

#     #############################################
#     print FH "\n################################\n";
#     if($PLOT_EPS) {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.win.err_ts.eps\"\n";
#     }
#     else {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.win.err_ts.png\"\n";
#     }
#     $local_cnt = 0;
#     print FH "plot ";
#     ## c) avg frequency in a time window
#     foreach my $this_win_size (@WINDOW_SIZE) {
#         print FH ", \\\n" if($local_cnt != 0);
#         $line_cnt = ($local_cnt % 12) + 1;
#         $cnt ++;
#         $local_cnt ++;
#         print FH "data_dir.\"\/$pure_name.$this_ip.err_ts.txt\" using 1:$cnt with points ls $line_cnt title \"win size=$this_win_size\"";
#     }


#     #############################################
#     print FH "\n################################\n";
#     if($PLOT_EPS) {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.ewma.err_ts.eps\"\n";
#     }
#     else {
#         print FH "set output figure_dir.\"\/$pure_name.$this_ip.ewma.err_ts.png\"\n";
#     }
#     $local_cnt = 0;
#     print FH "plot ";
#     ## d) EWMA
#     foreach my $this_alpha (@ALPHA) {
#         print FH ", \\\n" if($local_cnt != 0);
#         $line_cnt = ($local_cnt % 12) + 1;
#         $cnt ++;
#         $local_cnt ++;
#         print FH "data_dir.\"\/$pure_name.$this_ip.err_ts.txt\" using 1:$cnt with points ls $line_cnt title \"EWMA alpha=$this_alpha\"";
#     }


#     close FH;


#     my $cmd = "gnuplot $gnuplot_file";
#     `$cmd`;
#     $cmd = "rm $gnuplot_file";
#     `$cmd`;
# }


