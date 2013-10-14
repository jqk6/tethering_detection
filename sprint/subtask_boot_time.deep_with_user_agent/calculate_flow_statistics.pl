#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/05 @ Narus
##
## Get the flow statistics.
##   a) flow with User Agent
##   b) flow with Timestamp
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
##      perl calculate_flow_statistics.pl 49
##      perl calculate_flow_statistics.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
##################################################

use strict;
use List::Util qw(sum max min);
use MyUtil;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug
my $DEBUG3 = 1; ## print out detailed statistics
my $DEBUG4 = 0; ## print out detailed statistics for each packet

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
my $FIX_SRC_ADDR  = "^28\.";
# my $FIX_SRC_ADDR  = "^10.";
# my $FIX_SRC_ADDR  = "28.222.137.183";

## The IP to be plotted
# my $PLOT_IP       = "10.0.2.4"; 
# my $PLOT_IP       = "128.83";
# my $PLOT_IP       = "192.168";
my $PLOT_IP       = "28.222.245.159";

my $STATISTICS1   = 1;
my $STATISTICS2   = 1;

my $PKT_THRESHOLD         = 20;  ## the min num of packets should have per flow
my $FLOW_THRESHOLD        = 3;   ## number of flows per IP required
my $STABLE_THRESHOLD      = 1;   ## the stdev of frequency should small than this number
my $STABLE_PKT_THRESHOLD  = 10;  ## the min number of packets should have after the frequency becomes stable
my $FLOW_LEN_THRESHOLD    = 5;   ## the min length of flows (in seconds)
my $FREQ_THRESHOLD        = 3;   ## the stdev of flow frequencies from an IP should small than this number
my $BOOT_THRESHOLD        = 600;   ## the stdev of flow estimated boot times from an IP should small than this number
                                  ## the max boot time spance of a flow
my $BOOT_STABLE_THRESHOLD = 3;  ## start to estimate boot time after this number of interval (in seconds);
# my $BOOT_NUM_THRESHOLD    = $PKT_THRESHOLD;  ## number of packets per flow required for boot time heuristics
# my $BOOT_FLOW_THRESHOLD   = $FLOW_THRESHOLD;  ## number of flows per IP required for boot time heuristics
my $BOOT_FREQ_THRESHOLD   = 10;   ## the stdev of flow estimated boot times from an IP should small than this number
my @BOOT_POSSIBLE_FREQS   = (2, 10, 100, 128, 200, 1000);  ## possible frequencies for boot time heuristics
my $ALPHA                 = 0.7; ## the EWMA parameter for frequency estimation

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir");
my @devices         = ("HTC", "Samsung", "Samsung",  "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir");


#####
## variables
my $input_dir_timestamp  = "/data/ychen/sprint/text5";
my $input_dir_user_agent = "/data/ychen/sprint/text3";
my $output_dir = "./output_flow_statistics";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_freq.plot";

my $file_name;
my $file_name_ts;
my $file_name_ua;
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
if($ARGV[0] =~ /^\d+$/) {
    my $file_id = $ARGV[0];
    $file_name = "omni.out.$file_id.eth.pcap.txt";
    $file_name_ts = "$input_dir_timestamp/$file_name";
    $file_name_ua = "$input_dir_user_agent/$file_name";
}
else {
    $file_name = $ARGV[0];
    $file_name_ts = "/data/ychen/testbed/tcp_traces/text5/$file_name";
    $file_name_ua = "/data/ychen/testbed/tcp_traces/text3/$file_name";
    if(! -e $file_name_ts) {
        $file_name_ts = "/data/ychen/testbed/3g_measurement/text5/$file_name";
        $file_name_ua = "/data/ychen/testbed/3g_measurement/text3/$file_name";
    }
}
print "input file name = $file_name_ts\n" if($DEBUG2);
print "input file name = $file_name_ua\n" if($DEBUG2);


####################################################
## Read Files
####################################################

## TCP Timestamp
print STDERR "start to read TCP Timestamp data..\n" if($DEBUG2);
open FH, $file_name_ts or die $!."\n$file_name_ts";
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
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TX_TIME} }, $tcp_ts_val);
    push( @{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME} }, $time + $time_usec / 1000000);
    $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;
    $ip_info{IP}{$src}{TTL}{$ttl} = 1;
    $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{WIN}{$win} = 1;
    $ip_info{IP}{$src}{WIN}{$win} = 1;
    $ip_info{IP}{$src}{TIMESTAMP_EXIST} = 1;
    
}
close FH;


## User Agent
print STDERR "start to read User Agent data..\n" if($DEBUG2);
open FH, $file_name_ua or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    print "> $_" if($DEBUG1);
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len))."\n" if($DEBUG1);


    my $line = <FH>;
    print ">>> $line" if($DEBUG1);
    while($line = <FH>) {
        print ">>> $line" if($DEBUG1);
        last if($line eq "\n");
        next if($FIX_SRC  and (!($src =~ /$FIX_SRC_ADDR/ )));
        next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));


        my ($tag, $val) = split(/: |\r/, $line);
        chomp $tag;
        chomp $val;
        print "    ($tag, $val)\n" if($DEBUG1);

        ## User-Agent
        if($tag =~ /User.*Agent/i) {
            print "^^^ $val\n" if($DEBUG1);
            $ip_info{IP}{$src}{AGENT}{$val} = 1;
            $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{AGENT}{$val} = 1;
            $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;
            $ip_info{IP}{$src}{TTL}{$ttl} = 1;
            $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{WIN}{$win} = 1;
            $ip_info{IP}{$src}{WIN}{$win} = 1;
        }
    }


}
close FH;



############################################################
## Analyze Data
############################################################
my $total_flows = 0;
my $total_ips = 0;
my $flow_with_ua = 0;
my $flow_with_known_ua = 0;
my $ip_with_ua = 0;
my $ip_with_known_ua = 0;
my $flow_with_ts = 0;
my $flow_with_enough_ts = 0;
my $ip_with_ts = 0;
my $ip_with_enough_ts = 0;

print STDERR "start to process data..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    $total_ips ++;
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    $total_flows += (scalar(keys %{ $ip_info{IP}{$this_ip}{CONN} }));

    ## User Agent
    if(exists($ip_info{IP}{$this_ip}{AGENT})) {
        ## IP layer
        $ip_with_ua ++;

        my $ip_find_known_ua = 0;
        foreach my $this_agent (keys %{ $ip_info{IP}{$this_ip}{AGENT} }) {
            foreach my $os_ind (0 .. @OS_keywords-1) {
                my $os_keyword = $OS_keywords[$os_ind];
                if($this_agent =~ /$os_keyword/i) {
                    $ip_find_known_ua = 1;
                    last;
                }
            }
            last if($ip_find_known_ua == 1);
        }
        $ip_with_known_ua += $ip_find_known_ua;
        


        ## flow layer
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});

            $flow_with_ua ++;
            my $flow_find_known_ua = 0;
            foreach my $this_agent (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {
                foreach my $os_ind (0 .. @OS_keywords-1) {
                    my $os_keyword = $OS_keywords[$os_ind];
                    if($this_agent =~ /$os_keyword/i) {
                        $flow_find_known_ua = 1;
                        last;
                    }
                }
                last if($flow_find_known_ua == 1);
            }
            $flow_with_known_ua += $flow_find_known_ua;
        }

    }   ## end User Agent



    ## Timestamp
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    my $ip_ts_cnt = 0;
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME});

        $flow_with_ts ++;
        my $flow_ts_cnt = scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} });
        if($flow_ts_cnt > 30) {
            $flow_with_enough_ts ++;
        }
        $ip_ts_cnt += $flow_ts_cnt;
    }

    if($ip_ts_cnt > 0) {
        $ip_with_ts ++;
    }
    if($ip_ts_cnt > 30) {
        $ip_with_enough_ts ++;
    }

    ## end Timestamp

} ## end for each IP



open FH_ALL, ">> $output_dir/flows.txt" or die $!;
open FH, "> $output_dir/$file_name.flows.txt" or die $!;
print FH_ALL "".join(", ", ($total_ips, $ip_with_ua, $ip_with_known_ua, $ip_with_ts, $ip_with_enough_ts, 
                        $total_flows, $flow_with_ua, $flow_with_known_ua, $flow_with_ts, $flow_with_enough_ts) )."\n";
print FH "".join(", ", ($total_ips, $ip_with_ua, $ip_with_known_ua, $ip_with_ts, $ip_with_enough_ts, 
                        $total_flows, $flow_with_ua, $flow_with_known_ua, $flow_with_ts, $flow_with_enough_ts) )."\n";
close FH;
close FH_ALL;





