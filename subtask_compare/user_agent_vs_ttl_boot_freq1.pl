#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/06 @ Narus
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
##      perl user_agent_ttl_boot_freq1.pl 49
##      perl user_agent_ttl_boot_freq1.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
##################################################

use strict;
use List::Util qw(sum max min);
use MyUtil;
use Tethering;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 0; ## print more
my $DEBUG4 = 1; ## print false cases


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


my $FLOW_WITH_OS_ONLY = 1;  ## 1 to take into account flows with OS info

my $BOOT_TIME_FREQ = 1;  ## 0: to use estimated freq, 1 to use 100Hz
my $BOOT_TIME_FREQ1 = 0;
my $BOOT_TIME_INTERVAL_THRESHOLD = 3;  ## the boot time interval between two devices should be larger than this threshold
my $BOOT_TIME_SPAN_THRESHOLD = 1;  ## the boot time interval between packets should be smaller than this threshold
my $BOOT_TIME_SPAN_THRESHOLD1 = 10;
my $FLOW_PKT_NUM_THRESHOLD = 0;
my $FLOW_PKT_NUM_THRESHOLD1 = 5;
my $FLOW_DURATION_THRESHOLD = 0;
my $FLOW_DURATION_THRESHOLD1 = 5;

my @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);
my @CLOCK_FREQ1 = (10, 100, 128, 200, 1000);

my @MAJOR_TTLS = (60..68, 90..100, 120..128, 250..256);

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
                    ## IP - CONN - TTL

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
if($iteration == 0) {
    $BOOT_TIME_FREQ = 0;
    $BOOT_TIME_FREQ1 = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 3;
    $BOOT_TIME_SPAN_THRESHOLD = 1;
    $BOOT_TIME_SPAN_THRESHOLD1 = 1;
    $FLOW_PKT_NUM_THRESHOLD = 2;
    $FLOW_PKT_NUM_THRESHOLD1 = 5;
    $FLOW_DURATION_THRESHOLD = 0;
    $FLOW_DURATION_THRESHOLD1 = 5;
    @CLOCK_FREQ = (100);
    @CLOCK_FREQ1 = (10, 100, 128, 200, 1000);
    @MAJOR_TTLS = (60..68, 90..100, 120..128, 250..256);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}
elsif($iteration == 1) {
    $BOOT_TIME_FREQ = 1;
    $BOOT_TIME_FREQ1 = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 3;
    $BOOT_TIME_SPAN_THRESHOLD = 1;
    $BOOT_TIME_SPAN_THRESHOLD1 = 1;
    $FLOW_PKT_NUM_THRESHOLD = 0;
    $FLOW_PKT_NUM_THRESHOLD1 = 5;
    $FLOW_DURATION_THRESHOLD = 0;
    $FLOW_DURATION_THRESHOLD1 = 5;
    @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);
    @CLOCK_FREQ1 = (10, 100, 128, 200, 1000);
    @MAJOR_TTLS = (60..68, 90..100, 120..128, 250..256);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}
elsif($iteration == 2) {
    $BOOT_TIME_FREQ = 0;
    $BOOT_TIME_FREQ1 = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 600;
    $BOOT_TIME_SPAN_THRESHOLD = 2;
    $BOOT_TIME_SPAN_THRESHOLD1 = 1;
    $FLOW_PKT_NUM_THRESHOLD = 30;
    $FLOW_PKT_NUM_THRESHOLD1 = 5;
    $FLOW_DURATION_THRESHOLD = 5;
    $FLOW_DURATION_THRESHOLD1 = 5;
    @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);
    @CLOCK_FREQ1 = (10, 100, 128, 200, 1000);
    @MAJOR_TTLS = (60..68, 90..100, 120..128, 250..256);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}
elsif($iteration == 3) {
    $BOOT_TIME_FREQ = 1;
    $BOOT_TIME_FREQ1 = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 3;
    $BOOT_TIME_SPAN_THRESHOLD = 1;
    $BOOT_TIME_SPAN_THRESHOLD1 = 1;
    $FLOW_PKT_NUM_THRESHOLD = 0;
    $FLOW_PKT_NUM_THRESHOLD1 = 5;
    $FLOW_DURATION_THRESHOLD = 0;
    $FLOW_DURATION_THRESHOLD1 = 5;
    @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);
    @CLOCK_FREQ1 = (10, 100, 128, 200, 1000);
    @MAJOR_TTLS = (63, 127);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}
elsif($iteration == 4) {
    $BOOT_TIME_FREQ = 0;
    $BOOT_TIME_FREQ1 = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 600;
    $BOOT_TIME_SPAN_THRESHOLD = 2;
    $BOOT_TIME_SPAN_THRESHOLD1 = 1;
    $FLOW_PKT_NUM_THRESHOLD = 30;
    $FLOW_PKT_NUM_THRESHOLD1 = 5;
    $FLOW_DURATION_THRESHOLD = 5;
    $FLOW_DURATION_THRESHOLD1 = 5;
    @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);
    @CLOCK_FREQ1 = (10, 100, 128, 200, 1000);
    @MAJOR_TTLS = (63, 127);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}

##==================================================
else {
    die "wrong iter: $iteration\n";
}



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
            $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;
        }
    }
}
close FH;



############################################################
## Calculate boot time and identify OS
############################################################
print STDERR "start to Calculate boot time and identify OS..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    ## Flow:
    ##   IP - Flow |- TX_TIME (o)
    ##             |- RX_TIME (o)
    ##             |- BOOT_TIME
    ##             |- FREQ
    ##             |- FREQ1
    ##             |- User_Agent (o)
    ##             |- OS
    ##             |- TTL (o)
    ##
    ## Boot Time:
    ##   IP - GROUP_BOOT_TIME - FLOW |- TX_TIME
    ##                               |- RX_TIME
    ##                               |- BOOT_TIME
    ##                               |- FREQ
    ##                               |- FREQ1
    ##                               |- User_Agent
    ##                               |- OS
    ##                               |- TTL
    ## Frequency1:
    ##   IP - FREQ1 - FLOW |- TX_TIME
    ##                     |- RX_TIME
    ##                     |- BOOT_TIME
    ##                     |- FREQ
    ##                     |- User_Agent
    ##                     |- OS
    ##                     |- TTL
    ##
    ## OS:
    ##   IP - OS - FLOW |- TX_TIME
    ##                  |- RX_TIME
    ##                  |- BOOT_TIME
    ##                  |- FREQ
    ##                  |- FREQ1
    ##                  |- User_Agent
    ##                  |- TTL
    ##
    ## TTL:
    ##   IP - TTL - FLOW |- TX_TIME
    ##                   |- RX_TIME
    ##                   |- BOOT_TIME
    ##                   |- FREQ
    ##                   |- FREQ1
    ##                   |- User_Agent
    ##                   |- OS
    ##
    print "------------------------------\n" if($DEBUG3);
    if(exists($ip_info{IP}{$this_ip}{CONN})) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
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
                    $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn} = () if(!exists $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn});
                }
                print "  - OS: $os\n" if($DEBUG3);
            }

            if($FLOW_WITH_OS_ONLY) {
                next if($os eq "");
            }

            ## TTL of the flow
            my %ttl = ();
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
                print "  - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }))."\n" if($DEBUG3);
                
                foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
                    $ttl{$this_ttl} = 1;
                    
                    if(!($os eq "")) {
                        ## OS
                        $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{TTL}{$this_ttl} = 1;
                        ## TTL
                        $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{OS} = $os;
                    }
                    else {
                        ## TTL
                        $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn} = () if(!exists $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn});
                    }
                }
            }

            ## Boot time and frequency1 of the flow
            my ($freq, $boot_time);
            my ($freq1, $boot_time1);
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}) {
                ## boot time of the flow
                ($freq, $boot_time) = Tethering::_est_freq_boottime_enumeration(
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }, 
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} },
                                            \@CLOCK_FREQ,
                                            $BOOT_TIME_FREQ,
                                            $BOOT_TIME_SPAN_THRESHOLD,
                                            $FLOW_PKT_NUM_THRESHOLD,
                                            $FLOW_DURATION_THRESHOLD);
                ## frequency1 of the flow
                ($freq1, $boot_time1) = Tethering::_est_freq_boottime_enumeration(
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }, 
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} },
                                            \@CLOCK_FREQ1,
                                            $BOOT_TIME_FREQ1,
                                            $BOOT_TIME_SPAN_THRESHOLD1,
                                            $FLOW_PKT_NUM_THRESHOLD1,
                                            $FLOW_DURATION_THRESHOLD1);
                
                print "  - boot time: $boot_time\n" if($DEBUG3 and $freq > 0);
                print "  - freq: $freq\n" if($DEBUG3 and $freq > 0);
                print "  - freq1: $freq1\n" if($DEBUG3 and $freq1 > 0);

                ## OS
                if(!($os eq "")) {
                    @{ $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                    @{ $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                    %{ $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{AGENT} } = %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} };
                    $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                    $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                    $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{FREQ1} = $freq1 if($freq1 > 0);
                }

                ## Flow
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} = $os if(!($os eq ""));
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQ1} = $freq1 if($freq1 > 0);

                ## TTL
                foreach my $this_ttl (keys %ttl) {
                    @{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                    @{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                    %{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{AGENT} } = %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} } if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                    $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                    $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                    $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{FREQ1} = $freq1 if($freq1 > 0);
                }

                ## Frequency1
                if($freq1 > 0) {
                    @{ $ip_info{IP}{$this_ip}{FREQ1}{$freq1}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                    @{ $ip_info{IP}{$this_ip}{FREQ1}{$freq1}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                    %{ $ip_info{IP}{$this_ip}{FREQ1}{$freq1}{CONN}{$this_conn}{AGENT} } = %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} } if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                    $ip_info{IP}{$this_ip}{FREQ1}{$freq1}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                    $ip_info{IP}{$this_ip}{FREQ1}{$freq1}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                    $ip_info{IP}{$this_ip}{FREQ1}{$freq1}{CONN}{$this_conn}{OS} = $os if(!($os eq ""));
                    foreach my $this_ttl (keys %ttl) {
                        $ip_info{IP}{$this_ip}{FREQ1}{$freq1}{CONN}{$this_conn}{TTL}{$this_ttl} = 1;
                    }
                }

                ## Boot time
                if($freq > 0) {
                    my $found = 0;
                    if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}) {
                        foreach my $this_group_boot_time (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME} }) {
                            if(abs($this_group_boot_time - $boot_time) <= $BOOT_TIME_INTERVAL_THRESHOLD) {
                                ## same group
                                @{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                                @{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                                %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{AGENT} } = %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} } if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME} = $boot_time;
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ} = $freq;
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ1} = $freq1 if($freq1 > 0);
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{OS} = $os if(!($os eq ""));
                                foreach my $this_ttl (keys %ttl) {
                                    $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{TTL}{$this_ttl} = 1;
                                }

                                $found = 1;
                                last;
                            }
                        }
                    }
                    if($found == 0) {
                        ## new group
                        @{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                        @{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                        %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{AGENT} } = %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} } if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{BOOT_TIME} = $boot_time;
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{FREQ} = $freq;
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{FREQ1} = $freq1 if($freq1 > 0);
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{OS} = $os if(!($os eq ""));
                        foreach my $this_ttl (keys %ttl) {
                            $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{TTL}{$this_ttl} = 1;
                        }
                    }  ## end if not exist group_boo_time
                }  ## end if boot time exist
            }
        }
    }
}




############################################################
## Evaluate results
############################################################
## Flow:
##   IP - Flow |- TX_TIME (o)
##             |- RX_TIME (o)
##             |- BOOT_TIME
##             |- FREQ
##             |- FREQ1
##             |- User_Agent (o)
##             |- OS
##             |- TTL (o)
##
## Boot Time:
##   IP - GROUP_BOOT_TIME - FLOW |- TX_TIME
##                               |- RX_TIME
##                               |- BOOT_TIME
##                               |- FREQ
##                               |- FREQ1
##                               |- User_Agent
##                               |- OS
##                               |- TTL
## Frequency1:
##   IP - FREQ1 - FLOW |- TX_TIME
##                     |- RX_TIME
##                     |- BOOT_TIME
##                     |- FREQ
##                     |- User_Agent
##                     |- OS
##                     |- TTL
##
## OS:
##   IP - OS - FLOW |- TX_TIME
##                  |- RX_TIME
##                  |- BOOT_TIME
##                  |- FREQ
##                  |- FREQ1
##                  |- User_Agent
##                  |- TTL
##
## TTL:
##   IP - TTL - FLOW |- TX_TIME
##                   |- RX_TIME
##                   |- BOOT_TIME
##                   |- FREQ
##                   |- FREQ1
##                   |- User_Agent
##                   |- OS
##
print STDERR "start to Evaluate results..\n" if($DEBUG2);
my $cnt_ip = 0;
my $cnt_invalid_ip = 0;
my $cnt_invalid_ttl = 0;
my $cnt_invalid_boot = 0;
my $cnt_invalid_freq1 = 0;
my $cnt_invalid_comb = 0;
my $cnt_invalid_p_comb = 0;
my $cnt_invalid_n_comb = 0;
my $tp_ttl = 0;
my $tn_ttl = 0;
my $fp_ttl = 0;
my $fn_ttl = 0;
my $tp_boot = 0;
my $tn_boot = 0;
my $fp_boot = 0;
my $fn_boot = 0;
my $tp_freq1 = 0;
my $tn_freq1 = 0;
my $fp_freq1 = 0;
my $fn_freq1 = 0;
my $tp_comb = 0;
my $tn_comb = 0;
my $fp_comb = 0;
my $fn_comb = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{OS});
    print "==============================\n";
    print "$this_ip\n";


    ## OS
    my $num_os = 0;
    $num_os = scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) if(exists $ip_info{IP}{$this_ip}{OS});
    ## Boot time
    my $num_boot_time = 0;
    $num_boot_time = scalar(keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME} }) if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME});
    ## TTL
    my $num_ttl = 0;
    my $ttl_not_major = 0;
    # $num_ttl = scalar(keys %{ $ip_info{IP}{$this_ip}{TTL} }) if(exists $ip_info{IP}{$this_ip}{TTL});
    if(exists $ip_info{IP}{$this_ip}{TTL}) {
        foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{TTL} }) {
            ## if have OS, count this one
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN} }) {
                if(exists $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{OS}) {
                    $num_ttl ++;
                    last;
                }
            }

            ## see if this TTL is one of the major TTL
            if($ttl_not_major == 0) {
                my $found = 0;
                foreach my $this_major_ttl (@MAJOR_TTLS) {
                    if($this_major_ttl == $this_ttl) {
                        $found = 1;
                        last;
                    }
                }
                if($found == 0) {
                    $ttl_not_major = 1;
                }
            }
        }
    }
    ## Freq1
    my $num_freq1 = 0;
    $num_freq1 = scalar(keys %{ $ip_info{IP}{$this_ip}{FREQ1} }) if(exists $ip_info{IP}{$this_ip}{FREQ1});


    ##################
    ## Strat to check correctness
    ##################
    if($num_os >= 2) {
        $cnt_ip ++;

        ## TTL heuristics
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "TTL: True Positive\n";
            $tp_ttl ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            print "TTL False Negative\n";
            $fn_ttl ++;
        }
        else {
            $cnt_invalid_ttl ++;
        }

        ## Boot time heuristics
        if($num_boot_time >= 2) {
            print "Boot Time: True Positive\n";
            $tp_boot ++;
        }
        elsif($num_boot_time == 1) {
            print "Boot Time: False Negative\n";
            # $fn_boot ++;
            my $valid = validate_boot_flow_fn(\%ip_info, $this_ip);
            if($valid == 1) {
                $fn_boot ++;
            }
            else {
                $cnt_invalid_boot ++;
            }
        }
        else {
            $cnt_invalid_boot ++;
        }

        ## Freq1 heuristics
        if($num_freq1 >= 2) {
            print "Freq1: True Positive\n";
            $tp_freq1 ++;
        }
        elsif($num_freq1 == 1) {
            print "Freq1: False Negative\n";
            # $fn_freq1 ++;
            my $valid = validate_freq1_flow_fn(\%ip_info, $this_ip);
            if($valid == 1) {
                $fn_freq1 ++;
            }
            else {
                $cnt_invalid_freq1 ++;
            }
        }
        else {
            $cnt_invalid_freq1 ++;
        }

        ## combine heuristics
        my ($tmp_cnt_invalid, $tmp_tp, $tmp_tn, $tmp_fp, $tmp_fn, $tmp_cnt_invalid_p, $tmp_cnt_invalid_n) = combine_heuristic6(\%ip_info, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1);
        $cnt_invalid_comb += $tmp_cnt_invalid;
        $tp_comb += $tmp_tp;
        $tn_comb += $tmp_tn;
        $fp_comb += $tmp_fp;
        $fn_comb += $tmp_fn;
        $cnt_invalid_p_comb += $tmp_cnt_invalid_p;
        $cnt_invalid_n_comb += $tmp_cnt_invalid_n;
        
    }
    elsif($num_os == 1) {
        $cnt_ip ++;

        ## TTL heuristics
        if($num_ttl == 1 or $ttl_not_major == 0) {
            print "TTL: True Negative\n";
            $tn_ttl ++;
        }
        elsif($num_ttl >= 2 or $ttl_not_major == 1) {
            print "TTL: False Positive\n";
            $fp_ttl ++;
        }
        else {
            $cnt_invalid_ttl ++;
        }

        ## Boot time heuristics
        if($num_boot_time == 1) {
            print "Boot Time: True Negative\n";
            $tn_boot ++;
        }
        elsif($num_boot_time >= 2) {
            print "Boot Time: False Positive\n";
            # $fp_boot ++;
            my $valid = validate_boot_flow_fp(\%ip_info, $this_ip);
            if($valid == 1) {
                $fp_boot ++;
            }
            else {
                $cnt_invalid_boot ++;
            }
        }
        else {
            $cnt_invalid_boot ++;
        }

        ## Freq1 heuristics
        if($num_freq1 == 1) {
            print "Freq1: True Negative\n";
            $tn_freq1 ++;
        }
        elsif($num_freq1 >= 2) {
            print "Freq1: False Positive\n";
            # $fp_freq1 ++;
            my $valid = validate_freq1_flow_fp(\%ip_info, $this_ip);
            if($valid == 1) {
                $fp_freq1 ++;
            }
            else {
                $cnt_invalid_freq1 ++;
            }
        }
        else {
            $cnt_invalid_freq1 ++;
        }

        ## combine heuristics
        my ($tmp_cnt_invalid, $tmp_tp, $tmp_tn, $tmp_fp, $tmp_fn, $tmp_cnt_invalid_p, $tmp_cnt_invalid_n) = combine_heuristic6(\%ip_info, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1);
        $cnt_invalid_comb += $tmp_cnt_invalid;
        $tp_comb += $tmp_tp;
        $tn_comb += $tmp_tn;
        $fp_comb += $tmp_fp;
        $fn_comb += $tmp_fn;
        $cnt_invalid_p_comb += $tmp_cnt_invalid_p;
        $cnt_invalid_n_comb += $tmp_cnt_invalid_n;
    }
    else {
        print "Invalid: #OS=$num_os, #TTL=$num_ttl, #Boot=$num_boot_time\n";
        $cnt_invalid_ip ++;
    }

    ####################
    ## DEBUG: print details
    ####################
    if($DEBUG4) {
        ## OS 
        foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
            print "- OS: $this_os\n";

            next if(!exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN});
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN} }) {
                print "  - Flow: $this_conn ";
                if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}) {
                    print "(#pkt=".scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }).", dur=".($ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0])."):\n";
                }
                else {
                    print "\n";
                }

                ## Agent
                print "    - Agent: ".join(" ||| ", (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{AGENT} }))."\n";

                ## TTL
                if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{TTL}) {
                    print "    - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{TTL} }))."\n";
                }

                ## Boot time
                if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME}) {
                    print "    - BOOT_TIME: ".$ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME}."\n";
                    print "    - FREQ: ".$ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{FREQ}."\n";
                }

                ## Freq1
                if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{FREQ1}) {
                    print "    - FREQ1: ".$ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{FREQ1}."\n";
                }
            }
        }

        ## TTL
        print "\n";
        foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{TTL} }) {
            print "- TTL: $this_ttl\n";

            next if(!exists $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN});
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN} }) {
                print "  - Flow: $this_conn ";
                if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}) {
                    print "(#pkt=".scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }).", dur=".($ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0])."):\n";
                }
                else {
                    print "\n";
                }

                ## OS
                if(exists $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{OS}) {
                    print "    - OS: ".$ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{OS}."\n";
                    print "    - Agent: ".join(" ||| ", (keys %{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{AGENT} }))."\n";
                }

                ## Boot time
                if(exists $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{BOOT_TIME}) {
                    print "    - BOOT_TIME: ".$ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{BOOT_TIME}."\n";
                    print "    - FREQ: ".$ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{FREQ}."\n";
                }

                ## Freq1
                if(exists $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{FREQ1}) {
                    print "    - FREQ1: ".$ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{FREQ1}."\n";
                }
            }
        }

        ## Boot time
        print "\n";
        foreach my $this_group_boot_time (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME} }) {
            print "- Group Boot Time: $this_group_boot_time\n";

            next if(!exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN});
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN} }) {
                print "  - Flow: $this_conn ";
                if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}) {
                    print "(#pkt=".scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }).", dur=".($ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0])."):\n";
                }
                else {
                    print "\n";
                }

                ## OS
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{OS}) {
                    print "    - OS: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{OS}."\n";
                    print "    - Agent: ".join(" ||| ", (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{AGENT} }))."\n";
                }

                ## Boot time
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME}) {
                    print "    - BOOT_TIME: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME}."\n";
                    print "    - FREQ: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ}."\n";
                }

                ## TTL
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{TTL}) {
                    print "    - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{TTL} }) )."\n";
                }

                ## Freq1
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ1}) {
                    print "    - FREQ1: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ1}."\n";
                }
            }
        }
    } ## End DEBUG print details
} ## end for all IPs


############################################################
## Output
############################################################
print "\nvalid_ip, invalid_ip, TTL[invalid, tp, tn, fp, fn], Boot[invalid, tp, tn, fp, fn], Freq1[invalid, tp, tn, fp, fn]\n";
print "$cnt_ip, $cnt_invalid_ip\n";
print "TTL[$cnt_invalid_ttl, $tp_ttl, $tn_ttl, $fp_ttl, $fn_ttl]\n";
print "BOOT[$cnt_invalid_boot, $tp_boot, $tn_boot, $fp_boot, $fn_boot]\n";
print "Freq1[$cnt_invalid_freq1, $tp_freq1, $tn_freq1, $fp_freq1, $fn_freq1]\n";
print "Comb[$cnt_invalid_comb, $tp_comb, $tn_comb, $fp_comb, $fn_comb, $cnt_invalid_p_comb, $cnt_invalid_n_comb]\n";
print "\n";

open FH, ">> $output_dir/user_agent_vs_ttl_boot_freq1.$iteration.txt" or die $!;
print FH "$cnt_ip, $cnt_invalid_ip, $cnt_invalid_ttl, $tp_ttl, $tn_ttl, $fp_ttl, $fn_ttl, $cnt_invalid_boot, $tp_boot, $tn_boot, $fp_boot, $fn_boot, $cnt_invalid_freq1, $tp_freq1, $tn_freq1, $fp_freq1, $fn_freq1, $cnt_invalid_comb, $tp_comb, $tn_comb, $fp_comb, $fn_comb, $cnt_invalid_p_comb, $cnt_invalid_n_comb\n";
close FH;





1;


## Boot time
sub validate_boot_flow_fp {
    my ($ip_info_ref, $this_ip) = @_;

    my %ip_info = %$ip_info_ref;


    ## see if a group of boot_time miss OS
    my $valid = 1;
    foreach my $this_group_boot_time (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME} }) {
        print "  - group boot time: $this_group_boot_time\n" if($DEBUG1);

        ## check each flow of this group
        my $os_found = 0;
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN} }) {
            print "    - flow: $this_conn\n" if($DEBUG1);
            print "      - boot time: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME}."\n" if($DEBUG1);
            print "      - freq: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ}."\n" if($DEBUG1);

            if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{OS}) {
                print "      - OS: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{OS}."\n" if($DEBUG1);
                print "      - UserAgents: ".join(" |||| ", (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{AGENT} }) )."\n" if($DEBUG1);

                $os_found = 1;
                last;
            }
        }
        if($os_found == 0) {
            ## this group miss OS --> invalid IP
            $valid = 0;
            last;
        }
    }

    return $valid;
}

sub validate_boot_flow_fn {
    my ($ip_info_ref, $this_ip) = @_;
    my %ip_info = %$ip_info_ref;

    ## see if an OS miss boot time
    my $valid = 1;
    foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
        print "  - OS: $this_os\n" if($DEBUG1);

        ## check each flow of OS
        my $boot_found = 0;
        if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}) {
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN} }) {
                print "    - Flow: $this_conn\n" if($DEBUG1);

                if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME}) {
                    print "      - BOOT_TIME: ".$ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME}."\n" if($DEBUG1);

                    $boot_found = 1;
                    last;
                }
            }
        }
        if($boot_found == 0) {
            ## this OS miss boot time --> invalid IP
            $valid = 0;
            last;
        }
    }

    return $valid;
}

## Freq1
sub validate_freq1_flow_fp {
    my ($ip_info_ref, $this_ip) = @_;
    my %ip_info = %$ip_info_ref;

    ## see if a group of freq miss OS
    my $valid = 1;
    foreach my $this_freq (keys %{ $ip_info{IP}{$this_ip}{FREQ1} }) {
        print "  - freq: $this_freq\n" if($DEBUG1);

        ## check each flow of this freq
        my $os_found = 0;
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{FREQ1}{$this_freq}{CONN} }) {
            print "    - flow: $this_conn (# pkt=".scalar(@{ $ip_info{IP}{$this_ip}{FREQ1}{$this_freq}{CONN}{$this_conn}{RX_TIME} }).", dur=".($ip_info{IP}{$this_ip}{FREQ1}{$this_freq}{CONN}{$this_conn}{RX_TIME}[-1] - $ip_info{IP}{$this_ip}{FREQ1}{$this_freq}{CONN}{$this_conn}{RX_TIME}[0]).")\n" if($DEBUG1);
            
            if(exists $ip_info{IP}{$this_ip}{FREQ1}{$this_freq}{CONN}{$this_conn}{OS}) {
                print "      - OS: ".$ip_info{IP}{$this_ip}{FREQ1}{$this_freq}{CONN}{$this_conn}{OS}."\n" if($DEBUG1);
                print "      - UserAgents: ".join(" |||| ", (keys %{ $ip_info{IP}{$this_ip}{FREQ1}{$this_freq}{CONN}{$this_conn}{AGENT} }) )."\n" if($DEBUG1);

                $os_found = 1;
                last;
            }
        }
        if($os_found == 0) {
            ## this freq miss OS --> invalid IP
            $valid = 0;
            last;
        }
    }

    return $valid;
}

sub validate_freq1_flow_fn {
    my ($ip_info_ref, $this_ip) = @_;
    my %ip_info = %$ip_info_ref;


    ## see if an OS miss frequency
    my $valid = 1;
    foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
        print "  - OS: $this_os\n" if($DEBUG1);

        ## check each flow of OS
        my $freq_found = 0;
        if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}) {
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN} }) {
                print "    - Flow: $this_conn\n" if($DEBUG1);

                if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{FREQ1}) {
                    print "      - Frequency: ".$ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{FREQ1}."\n" if($DEBUG1);

                    $freq_found = 1;
                    last;
                }
            }
        }
        if($freq_found == 0) {
            ## this OS miss freq --> invalid IP
            $valid = 0;
            last;
        }
    }

    return $valid;
}


## Combine Heuristics
sub combine_heuristic1 {
    my ($ip_info_ref, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1) = @_;
    my %ip_info = %$ip_info_ref;

    my $cnt_invalid = 0;
    my $cnt_invalid_p = 0;
    my $cnt_invalid_n = 0;
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;

    if($num_os >= 2) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: True Positive\n";
            $tp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_boot_time >= 2 and $num_freq1 >= 2) {
                print "Combine: True Positive\n";
                $tp ++;
            }
            elsif($num_boot_time == 1 and $num_freq1 >= 2) {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
            elsif($num_boot_time >= 2 and $num_freq1 == 1) {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
            elsif($num_boot_time == 1 and $num_freq1 == 1) {
                my $valid_boot = validate_boot_flow_fn(\%ip_info, $this_ip);
                my $valid_freq1 = validate_freq1_flow_fn(\%ip_info, $this_ip);
                if($valid_boot == 1 and $valid_freq1 == 1) {
                    print "Combine: False Negative\n";
                    $fn ++;
                }
                else {
                    $cnt_invalid ++;
                    $cnt_invalid_p ++;
                }
            }
            else {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_p ++;
        }
    }
    elsif($num_os == 1) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: False Positive\n";
            $fp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_boot_time >= 2 and $num_freq1 >= 2) {
                my $valid_boot = validate_boot_flow_fp(\%ip_info, $this_ip);
                my $valid_freq1 = validate_freq1_flow_fp(\%ip_info, $this_ip);
                if($valid_boot == 1 and $valid_freq1 == 1) {
                    print "Combine: False Positive\n";
                    $fp ++;
                }
                else {
                    $cnt_invalid ++;
                    $cnt_invalid_n ++;
                }
            }
            elsif($num_boot_time == 1 and $num_freq1 >= 2) {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
            elsif($num_boot_time >= 2 and $num_freq1 == 1) {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
            elsif($num_boot_time == 1 and $num_freq1 == 1) {
                print "Combine: True Positive\n";
                $tn ++;
            }
            else {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_n ++;
        }
    }
    die if($cnt_invalid>1 or $tp>1 or $tn>1 or $fp>1 or $fn>1);

    return ($cnt_invalid, $tp, $tn, $fp, $fn, $cnt_invalid_p, $cnt_invalid_n);
}


sub combine_heuristic2 {
    my ($ip_info_ref, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1) = @_;
    my %ip_info = %$ip_info_ref;

    my $cnt_invalid = 0;
    my $cnt_invalid_p = 0;
    my $cnt_invalid_n = 0;
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;

    if($num_os >= 2) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: True Positive\n";
            $tp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_boot_time >= 2 and $num_freq1 >= 2) {
                print "Combine: True Positive\n";
                $tp ++;
            }
            elsif($num_boot_time == 1 and $num_freq1 >= 2) {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
            elsif($num_boot_time >= 2 and $num_freq1 == 1) {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
            elsif($num_boot_time == 1 and $num_freq1 == 1) {
                my $valid_boot = validate_boot_flow_fn(\%ip_info, $this_ip);
                my $valid_freq1 = validate_freq1_flow_fn(\%ip_info, $this_ip);
                if($valid_boot == 1 and $valid_freq1 == 1) {
                    print "Combine: False Negative\n";
                    $fn ++;
                }
                else {
                    $cnt_invalid ++;
                    $cnt_invalid_p ++;
                }
            }
            else {
                ## no boot time or freq1
                print "Combine: False Negative\n";
                $fn ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_p ++;
        }
    }
    elsif($num_os == 1) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: False Positive\n";
            $fp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_boot_time >= 2 and $num_freq1 >= 2) {
                my $valid_boot = validate_boot_flow_fp(\%ip_info, $this_ip);
                my $valid_freq1 = validate_freq1_flow_fp(\%ip_info, $this_ip);
                if($valid_boot == 1 and $valid_freq1 == 1) {
                    print "Combine: False Positive\n";
                    $fp ++;
                }
                else {
                    $cnt_invalid ++;
                    $cnt_invalid_n ++;
                }
            }
            elsif($num_boot_time == 1 and $num_freq1 >= 2) {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
            elsif($num_boot_time >= 2 and $num_freq1 == 1) {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
            elsif($num_boot_time == 1 and $num_freq1 == 1) {
                print "Combine: True Positive\n";
                $tn ++;
            }
            else {
                ## no boot time or freq1
                print "Combine: True Positive\n";
                $tn ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_n ++;
        }
    }

    return ($cnt_invalid, $tp, $tn, $fp, $fn, $cnt_invalid_p, $cnt_invalid_n);
}

sub combine_heuristic3 {
    my ($ip_info_ref, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1) = @_;
    my %ip_info = %$ip_info_ref;

    my $cnt_invalid = 0;
    my $cnt_invalid_p = 0;
    my $cnt_invalid_n = 0;
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;

    if($num_os >= 2) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: True Positive\n";
            $tp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_freq1 >= 2) {
                print "Combine: True Positive\n";
                $tp ++;
            }
            else {
                print "Combine: False Negative\n";
                $fn ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_p ++;
        }
    }
    elsif($num_os == 1) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: False Positive\n";
            $fp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_freq1 >= 2) {
                my $valid_freq1 = validate_freq1_flow_fp(\%ip_info, $this_ip);
                if($valid_freq1 == 1) {
                    print "Combine: False Positive\n";
                    $fp ++;
                }
                else {
                    print "Combine: True Negative\n";
                    $tn ++;
                }
            }
            else {
                ## no boot time or freq1
                print "Combine: True Positive\n";
                $tn ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_n ++;
        }
    }

    return ($cnt_invalid, $tp, $tn, $fp, $fn, $cnt_invalid_p, $cnt_invalid_n);
}


sub combine_heuristic4 {
    my ($ip_info_ref, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1) = @_;
    my %ip_info = %$ip_info_ref;

    my $cnt_invalid = 0;
    my $cnt_invalid_p = 0;
    my $cnt_invalid_n = 0;
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;

    if($num_os >= 2) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: True Positive\n";
            $tp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_freq1 == 1 and validate_freq1_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: False Negative\n";
                $fn ++;
            }
            # elsif($num_boot_time == 1 and validate_boot_flow_fn(\%ip_info, $this_ip) == 1) {
            #     print "Combine: False Negative\n";
            # }
            else {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_p ++;
        }
    }
    elsif($num_os == 1) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: False Positive\n";
            $fp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_freq1 == 1 and validate_freq1_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: True Negative\n";
                $tn ++;
            }
            # elsif($num_boot_time == 1 and validate_boot_flow_fn(\%ip_info, $this_ip) == 1) {
            #     print "Combine: True Negative\n";
            # }
            else {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_n ++;
        }
    }

    return ($cnt_invalid, $tp, $tn, $fp, $fn, $cnt_invalid_p, $cnt_invalid_n);
}



sub combine_heuristic5 {
    my ($ip_info_ref, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1) = @_;
    my %ip_info = %$ip_info_ref;

    my $cnt_invalid = 0;
    my $cnt_invalid_p = 0;
    my $cnt_invalid_n = 0;
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;

    if($num_os >= 2) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: True Positive\n";
            $tp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            # if($num_freq1 == 1 and validate_freq1_flow_fn(\%ip_info, $this_ip) == 1) {
            #     print "Combine: False Negative\n";
            #     $fn ++;
            # }
            if($num_boot_time == 1 and validate_boot_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: False Negative\n";
                $fn ++;
            }
            else {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_p ++;
        }
    }
    elsif($num_os == 1) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: False Positive\n";
            $fp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            # if($num_freq1 == 1 and validate_freq1_flow_fn(\%ip_info, $this_ip) == 1) {
            #     print "Combine: True Negative\n";
            #     $tn ++;
            # }
            if($num_boot_time == 1 and validate_boot_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: True Negative\n";
                $tn ++;
            }
            else {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_n ++;
        }
    }

    return ($cnt_invalid, $tp, $tn, $fp, $fn, $cnt_invalid_p, $cnt_invalid_n);
}



sub combine_heuristic6 {
    my ($ip_info_ref, $this_ip, $num_os, $num_ttl, $ttl_not_major, $num_boot_time, $num_freq1) = @_;
    my %ip_info = %$ip_info_ref;

    my $cnt_invalid = 0;
    my $cnt_invalid_p = 0;
    my $cnt_invalid_n = 0;
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;

    if($num_os >= 2) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: True Positive\n";
            $tp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_freq1 == 1 and validate_freq1_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: False Negative\n";
                $fn ++;
            }
            elsif($num_boot_time == 1 and validate_boot_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: False Negative\n";
                $fn ++;
            }
            else {
                $cnt_invalid ++;
                $cnt_invalid_p ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_p ++
        }
    }
    elsif($num_os == 1) {
        if($num_ttl >= 2 or $ttl_not_major == 1) {
            print "Combine: False Positive\n";
            $fp ++;
        }
        elsif($num_ttl == 1 or $ttl_not_major == 0) {
            if($num_freq1 == 1 and validate_freq1_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: True Negative\n";
                $tn ++;
            }
            elsif($num_boot_time == 1 and validate_boot_flow_fn(\%ip_info, $this_ip) == 1) {
                print "Combine: True Negative\n";
                $tn ++;
            }
            else {
                $cnt_invalid ++;
                $cnt_invalid_n ++;
            }
        }
        else {
            $cnt_invalid ++;
            $cnt_invalid_n ++;
        }
    }

    return ($cnt_invalid, $tp, $tn, $fp, $fn, $cnt_invalid_p, $cnt_invalid_n);
}
