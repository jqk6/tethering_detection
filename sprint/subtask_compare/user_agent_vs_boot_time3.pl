#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/16 @ Narus
##
## Compare the result of User Agent and boot time heuristic
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
##      perl user_agent_vs_boot_time3.pl 49 0
##      perl user_agent_vs_boot_time3.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt 0
##################################################

use strict;
use List::Util qw(sum max min);
use MyUtil;
use Tethering;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 0; ## print progress
my $DEBUG3 = 0; ## print more
my $DEBUG4 = 0; ## print false cases


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

my $FLOW_WITH_OS_ONLY   = 1;  ## 1 to take into account flows with OS info
my $LARGEST_FREQ_THRESH = 1000;
my $MAX_INTERVAL_THRESH = 1000;

my @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux", "Xbox");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");
my @devices         = ("HTC", "Samsung", "Samsung",  "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");


#####
## variables
my $input_dir_timestamp  = "/data/ychen/sprint/text5";
my $input_dir_user_agent = "/data/ychen/sprint/text3";
my $output_dir = "./output";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_freq.plot";

my $file_name;
my $file_name_ts;
my $file_name_ua;
my $iteration;

my %ip_info;        ## IP
                    ## IP - CONN - TX_TIME
                    ## IP - CONN - RX_TIME
                    ## IP - CONN - AGENT

#####
## check input
if(@ARGV != 2) {
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
$iteration = $ARGV[1] + 0;
print "input file name = $file_name_ts\n" if($DEBUG2);
print "input file name = $file_name_ua\n" if($DEBUG2);




####################################################
## Iteration setting
## Observations:
## - $BOOT_TIME_INTERVAL_THRESHOLD = 80, 600, 3600
##   XX: does not change much
## - $BOOT_TIME_SPAN_THRESHOLD = 1, 5, 10
##   XX: does not change much
## - $FLOW_PKT_NUM_THRESHOLD from 10 to 2
##   $FLOW_DURATION_THRESHOLD from 1 to 0.2
##   XX: only increase # of true and false negative 
####################################################
@OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
@OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
my @freq_thresh = (100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000);
my @itvl_thresh = (100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000);
$LARGEST_FREQ_THRESH = $freq_thresh[$iteration];
$MAX_INTERVAL_THRESH = $itvl_thresh[$iteration];
# if($iteration == 0) {
#     $LARGEST_FREQ_THRESH = 100;
#     $MAX_INTERVAL_THRESH = 100;
# }
##==================================================
# else {
#     die "wrong iter: $iteration\n";
# }



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

    push( @{ $ip_info{IP}{$src}{TX_TIME_ALL} }, $tcp_ts_val);
    push( @{ $ip_info{IP}{$src}{RX_TIME_ALL} }, $time + $time_usec / 1000000);
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
    while($line = <FH>) {
        last if($line eq "\n");
        next if($FIX_SRC  and (!($src =~ /$FIX_SRC_ADDR/ )));
        next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));


        my ($tag, $val) = split(/: |\r/, $line);
        chomp $tag;
        chomp $val;
        print "    ($tag, $val)\n" if($DEBUG1);

        ## User-Agent
        if($tag =~ /User.*Agent/i) {
            $ip_info{IP}{$src}{AGENT}{$val} = 1;
            $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{AGENT}{$val} = 1;
        }
    }
}
close FH;



############################################################
## identify OS
############################################################
print STDERR "start to Calculate boot time and identify OS..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{CONN}));

    ## Flow:
    ##   IP - Flow |- TX_TIME
    ##             |- RX_TIME
    ##             |- User_Agent
    ##             |- OS
    ##
    ## OS:
    ##   IP |- OS |- RX_TIME - TX_TIME
    ##      |
    ##      |- RX_TIME - TX_TIME
    ##

    print "------------------------------\n" if($DEBUG3);
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists($ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}));
        print "$this_ip -- $this_conn: \n" if($DEBUG3);

        ## OS of the flow
        my $os = "";
        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
            my @tmp_user_agents = (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} });
            # my @os = Tethering::identify_os(\@tmp_user_agents);
            my @os = Tethering::_identify_os(\@tmp_user_agents, \@OS_keywords, \@OSs);
            die "one flow should just have one OS\n" if(scalar(@os) > 1);

            if(scalar(@os) == 1) {
                $os = $os[0];
                foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })-1) {
                    my $tx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$ind];
                    my $rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind];
                    
                    $ip_info{IP}{$this_ip}{OS}{$os}{RX_TIME}{$rx_time}{TX_TIME}{$tx_time} = 1;
                    $ip_info{IP}{$this_ip}{RX_TIME}{$rx_time}{TX_TIME}{$tx_time} = 1;
                }
            }
            print "  - OS: $os\n" if($DEBUG3);
        }

        if($FLOW_WITH_OS_ONLY) {
            next if($os eq "");
        }
    }
}



############################################################
## See if flows with the same OS have continuous Timestamp
############################################################
print STDERR "start to check timestamp..\n" if($DEBUG2);
my $cnt_ip = 0;
my $cnt_invalid_ip = 0;
my $tp = 0;
my $tn = 0;
my $fp = 0;
my $fn = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{OS}));
    $cnt_ip ++;


    ## check the continuity of Timestamp
    my @tx_times = ();
    my @rx_times = ();

    foreach my $this_rx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{RX_TIME} })) {
        foreach my $this_tx_time (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{RX_TIME}{$this_rx_time}{TX_TIME} })) {
            push(@tx_times, $this_tx_time);
            push(@rx_times, $this_rx_time);
        }
    }

    my $continuity = Tethering::_check_timestamp_continuity(\@rx_times, \@tx_times, $LARGEST_FREQ_THRESH);

    ## evaluation
    if(scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) == 1 and $continuity == 1) {
        $tn ++;

        if($DEBUG4) {
            print "- $this_ip\n";
            print "  True Negative\n";
            print "  - OS: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{OS} }))."\n";
            print "  - RX time: ".join(", ", @rx_times)."\n";
            print "  - TS: ".join(", ", @tx_times)."\n";
            print "  - RX time all: ".join(", ", @{ $ip_info{IP}{$this_ip}{RX_TIME_ALL} })."\n";
            print "  - TS all: ".join(", ", @{ $ip_info{IP}{$this_ip}{TX_TIME_ALL} })."\n";
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
                next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                print "  - CONN: $this_conn\n";
                print "    - Agents: ".join(" ||| ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }))."\n";
            }
            print "\n";
        }
    }
    elsif(scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) == 1 and $continuity != 1) {
        $fp ++;

        if($DEBUG4) {
            print "- $this_ip\n";
            print "  False Positive\n";
            print "  - OS: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{OS} }))."\n";
            print "  - RX time: ".join(", ", @rx_times)."\n";
            print "  - TS: ".join(", ", @tx_times)."\n";
            print "  - RX time all: ".join(", ", @{ $ip_info{IP}{$this_ip}{RX_TIME_ALL} })."\n";
            print "  - TS all: ".join(", ", @{ $ip_info{IP}{$this_ip}{TX_TIME_ALL} })."\n";
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
                next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                print "  - CONN: $this_conn\n";
                print "    - Agents: ".join(" ||| ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }))."\n";
            }
            print "\n";
        }
    }
    elsif(scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) > 1 and $continuity == 1) {
        $fn ++;

        if($DEBUG4) {
            print "- $this_ip\n";
            print "  False Negative\n";
            print "  - OS: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{OS} }))."\n";
            print "  - RX time: ".join(", ", @rx_times)."\n";
            print "  - TS: ".join(", ", @tx_times)."\n";
            print "  - RX time all: ".join(", ", @{ $ip_info{IP}{$this_ip}{RX_TIME_ALL} })."\n";
            print "  - TS all: ".join(", ", @{ $ip_info{IP}{$this_ip}{TX_TIME_ALL} })."\n";
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
                next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                print "  - CONN: $this_conn\n";
                print "    - Agents: ".join(" ||| ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }))."\n";
            }
            print "\n";
        }
    }
    elsif(scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) > 1 and $continuity != 1) {
        $tp ++;

        if($DEBUG4) {
            print "- $this_ip\n";
            print "  True Positive\n";
            print "  - OS: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{OS} }))."\n";
            print "  - RX time: ".join(", ", @rx_times)."\n";
            print "  - TS: ".join(", ", @tx_times)."\n";
            print "  - RX time all: ".join(", ", @{ $ip_info{IP}{$this_ip}{RX_TIME_ALL} })."\n";
            print "  - TS all: ".join(", ", @{ $ip_info{IP}{$this_ip}{TX_TIME_ALL} })."\n";
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
                next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                print "  - CONN: $this_conn\n";
                print "    - Agents: ".join(" ||| ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }))."\n";
            }
            print "\n";
        }
    }
    else {
        die "unknown case\n";
    }
}


############################################################
## Output
############################################################
print STDERR "start to generate output..\n" if($DEBUG2);
open FH_ALL, ">> $output_dir/user_agent_vs_boot_time3.$iteration.txt" or die $!;
print FH_ALL "$cnt_ip, $tp, $tn, $fp, $fn\n";
close FH_ALL;

print "\n valid_ip, tp, tn, fp, fn\n";
print "$cnt_ip, $tp, $tn, $fp, $fn\n";


