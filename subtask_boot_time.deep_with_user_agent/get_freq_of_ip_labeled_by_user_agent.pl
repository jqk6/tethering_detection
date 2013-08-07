#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/30 @ Narus
##
## Get the frequency per flow from IP which are marked as tethering by User Agent.
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
##      perl get_freq_of_ip_labeled_by_user_agent.pl 49
##      perl get_freq_of_ip_labeled_by_user_agent.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
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

## Analyze the OS and device listed in User-Agent
print STDERR "start to search OS and device keywords..\n" if($DEBUG1);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{AGENT}));
    print $this_ip.": (".scalar(keys %{ $ip_info{IP}{$this_ip}{AGENT} }).")\n" if($DEBUG1);


    ###########
    ## for this IP, if there is multiple OS/Devices
    foreach my $this_agents (keys %{ $ip_info{IP}{$this_ip}{AGENT} }) {
        print "   - ".$this_agents."\n"  if($DEBUG1);


        ## OSs: Windows, Microsoft, Android, MAC
        foreach my $os_ind (0 .. @OS_keywords-1) {
            my $os_keyword = $OS_keywords[$os_ind];
            my $os         = $OSs[$os_ind];

            if($this_agents =~ /$os_keyword/i) {
                $ip_info{IP}{$this_ip}{OS}{$os} = 1;

                print "    >> $os\n" if($DEBUG1);
                
                last;
            }
        }
        

        ## device: HTC, Samsung, LGE, NOKIA, Windows Phone, iPhone, iPad, MacBookAir 
        foreach my $device_ind (0 .. @device_keywords-1) {
            my $device_keyword = $device_keywords[$device_ind];
            my $device         = $devices[$device_ind];

            if($this_agents =~ /$device_keyword/i) {
                $ip_info{IP}{$this_ip}{DEVICE}{$device} = 1;

                print "    >> $device\n" if($DEBUG1);

                last;
            }
        }
        
    }
    print "\n" if($DEBUG1);

    my $num_OS = scalar(keys %{ $ip_info{IP}{$this_ip}{OS} });
    my $num_Device = scalar(keys %{ $ip_info{IP}{$this_ip}{DEVICE} });

    if($num_OS > 1 or $num_Device > 1) {
        $ip_info{IP}{$this_ip}{DETECTED_BY_UA} = 1;
    }
    else {
        $ip_info{IP}{$this_ip}{DETECTED_BY_UA} = 0;
    }


    ###########
    ## for this connections, if there is multiple OS/Devices
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});

        foreach my $this_agents (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {

            ## OSs: Windows, Microsoft, Android, MAC
            foreach my $os_ind (0 .. @OS_keywords-1) {
                my $os_keyword = $OS_keywords[$os_ind];
                my $os         = $OSs[$os_ind];

                if($this_agents =~ /$os_keyword/i) {
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS}{$os} = 1;
                    last;
                }
            }

            ## device: HTC, Samsung, LGE, NOKIA, Windows Phone, iPhone, iPad, MacBookAir 
            foreach my $device_ind (0 .. @device_keywords-1) {
                my $device_keyword = $device_keywords[$device_ind];
                my $device         = $devices[$device_ind];

                if($this_agents =~ /$device_keyword/i) {
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE}{$device} = 1;
                    last;
                }
            }
            
        }

        $num_OS = scalar(keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} });
        $num_Device = scalar(keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} });

        if($num_OS > 1 or $num_Device > 1) {
            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DETECTED_BY_UA} = 1;

            if($DEBUG0) {
                print "$this_ip - $this_conn\n";
                foreach my $this_agents (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {
                    print "$this_agents\n";
                }
                die "this connection have multiple UAs\n";
            }
        }
        else {
            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DETECTED_BY_UA} = 0;
        }
    }
}



#####
## Calculate frequency
print STDERR "start to calculate frequency data..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{CONN}));

    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} } ) {
        next if(!exists($ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}));

        my $this_length  = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1] - 
                           $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0];
        my $this_num_pkt = scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} });


        print "$this_ip - $this_conn (".scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })."), len=".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1]."-".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0]."=".$this_length."\n" if($DEBUG1);

        ## check if the flow is long enough
        next if($this_length < $FLOW_LEN_THRESHOLD);
        ## check if the flow has enough packets
        next if($this_num_pkt < $PKT_THRESHOLD);


        my $first_tx_time = -1;
        my $first_rx_time = -1;
        my $est_freq = -1;
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
            
            ## update frequency
            if($est_freq == -1) {
                $est_freq = $this_freq;
            }
            else {
                $est_freq = $this_freq * $ALPHA + (1 - $ALPHA) * $est_freq;
            }

            ## calculate boot time
            # next if($this_rx_time - $first_rx_time < $BOOT_STABLE_THRESHOLD);
            # next if($est_freq == 0);
            # my $this_boot_time = $this_rx_time - $this_tx_time / $est_freq;
            # push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} }, $this_boot_time);
            # push(@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }, $this_boot_time);

        }  ## end for each packet

        # my @tmp = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} };
        # my $boo_time_stdev = MyUtil::stdev(\@tmp);
        # if($boo_time_stdev < $BOOT_THRESHOLD) {
        #     # push(@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }, @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} });
        #     push(@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }, MyUtil::average(\@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} }) );
        # }
        # push(@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }, 
        #      MyUtil::average( \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} }) );
    }  ## end for each conn
}  ## end for each ip


#####
## calculate boot time
print STDERR "start to calculate boot time..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{CONN}));


    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} } ) {
        next if(!exists($ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}));
        # next if(scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} }) < $PKT_THRESHOLD);
        my $this_length  = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1] - 
                           $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0];
        next if($this_length < $FLOW_LEN_THRESHOLD);


        my $min_time_span = $BOOT_THRESHOLD + 1;
        my $min_time_span_freq = 0;
        my $min_time_span_boot_time = 0;
        foreach my $this_freq (@BOOT_POSSIBLE_FREQS) {
            my @this_boot_times = ();
            foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} })-1) {
                my $this_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind];
                my $this_tx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$ind];

                my $this_boot_time = $this_rx_time - $this_tx_time / $this_freq;
                push(@this_boot_times, $this_boot_time);
            }


            if($DEBUG1) {
                if($this_freq == 10 or $this_freq == 100 or $this_freq == 125 or $this_freq == 1000) {
                    print "- $this_conn, freq = $this_freq\n" ;
                    print "    - ".MyUtil::average(\@this_boot_times)."\n";    
                    
                    print "    - ";
                    foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} })-1) {
                        my $this_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind];
                        my $this_tx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}[$ind];
                        my $this_boot_time = $this_rx_time - $this_tx_time / $this_freq;
                        print "($this_rx_time, $this_tx_time, $this_boot_time), ";
                    }
                    print "\n";
                    
                }
            }

            
            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{$this_freq}{BOOT_TIME} = MyUtil::average(\@this_boot_times);

            my $max_boot_time = max(@this_boot_times);
            my $min_boot_time = min(@this_boot_times);
            my $this_boot_time_span = abs($max_boot_time - $min_boot_time);
            if($this_boot_time_span < $min_time_span) {
                $min_time_span = $this_boot_time_span;
                $min_time_span_freq = $this_freq;
                $min_time_span_boot_time = MyUtil::average(\@this_boot_times);
            }
        }
        # if($min_time_span < $BOOT_THRESHOLD) {
        if($min_time_span < 3) {
            push(@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }, $min_time_span_boot_time );
            push(@{ $ip_info{IP}{$this_ip}{BOOT_TIME_FREQ} }, $min_time_span_freq );

            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} = $min_time_span_boot_time;
            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME_FREQ} = $min_time_span_freq;
        }
    }
}


############################################################
## Heuristics
############################################################

#####
## clock frequency heuristics: if the stable frequencies from flows of an IP are the same
print STDERR "start to run clock frequency heuristics..\n" if($DEBUG2);
my $num_flow_become_stable = 0;
my $num_flow = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{CONN}));
    next if(scalar(keys %{ $ip_info{IP}{$this_ip}{CONN} }) < $FLOW_THRESHOLD);

    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} } ) {
        next if(!exists($ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}));

        my $first_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0];
        my $stable_time = -1;
        my $stable_freq = 0;

        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} })-$STABLE_PKT_THRESHOLD) {
            my $this_rx_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME}[$ind];
            my $this_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}[$ind];
            my @tmp1 = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} };
            my @tmp2 = @tmp1[$ind .. scalar(@tmp1) - 1];
            my $this_stdev = MyUtil::stdev(\@tmp2);
            $stable_freq = MyUtil::average(\@tmp2);
            print "$this_stdev ($this_freq), " if($DEBUG1);
            if($this_stdev < $STABLE_THRESHOLD) {
                $stable_time = $this_rx_time - $first_rx_time;

                if($DEBUG1) {
                    print "\n------------------------------------\n";
                    foreach my $ind2 (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} })-1) {
                        my $tmp_time = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS_RX_TIME}[$ind2];
                        my $tmp_freq = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}[$ind2];
                        print "$tmp_freq, $tmp_time\n";
                    }
                    print "stable time = $stable_time, freq = $stable_freq\n";
                }
                last;
            }
        }
        print "\n" if($DEBUG1);

        $num_flow ++;
        if($stable_time > 0) {
            ## become stable
            $num_flow_become_stable ++;
            push(@{ $ip_info{IP}{$this_ip}{STABLE_FREQ} }, $stable_freq);
            push(@{ $ip_info{IP}{$this_ip}{STABLE_FREQ_CONN} }, $this_conn);

            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ} = $stable_freq;
        }
    }

    if(exists $ip_info{IP}{$this_ip}{STABLE_FREQ}) {
        # my @tmp = @{ $ip_info{IP}{$this_ip}{STABLE_FREQ} };
        # next if(scalar(@{ $ip_info{IP}{$this_ip}{STABLE_FREQ} }) < 3);
        my $stdev_freq_of_ip = MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{STABLE_FREQ} });
        if($stdev_freq_of_ip > $FREQ_THRESHOLD) {
            $ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} = 1;
        }
        else {
            $ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} = 0;
        }
    }
}


#####
## Boot Time Heuristics
print STDERR "start to run Boot Time Heuristics..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{CONN}));
    
    # foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} } ) {
    #     next if(!exists($ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME}) or
    #             scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} }) == 0);

    #     my @tmp = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} };
    #     my $boo_time_stdev = MyUtil::stdev(\@tmp);

    #     if($boo_time_stdev > $BOOT_THRESHOLD) {
    #         print "=============================\n";
    #         print "boot time diversity in a flow is larger than the threshold\n";
    #         print "$this_ip - $this_conn\nboot time: ";
    #         print join(", ", @tmp)."\n";
    #         print "stdev = $boo_time_stdev\n";
    #         print "=============================\n";
    #         die;
    #     }
    # }
    
    next if(!exists($ip_info{IP}{$this_ip}{BOOT_TIME}));
    next if(scalar(@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }) < $FLOW_THRESHOLD);
    my @tmp = @{ $ip_info{IP}{$this_ip}{BOOT_TIME} };
    my $boo_time_stdev = MyUtil::stdev(\@tmp);
    if($boo_time_stdev > $BOOT_THRESHOLD) {
        $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} = 1;

        ## find the majority freq
        my %maj_freq = ();
        foreach my $this_freq (@{ $ip_info{IP}{$this_ip}{BOOT_TIME_FREQ} }) {
            $maj_freq{$this_freq} ++;
        }
        my $maj_freq = 0;
        my $maj_freq_cnt = 0;
        foreach my $this_freq (keys %maj_freq) {
            if($maj_freq{$this_freq} > $maj_freq_cnt) {
                $maj_freq_cnt = $maj_freq{$this_freq};
                $maj_freq = $this_freq;
            }
        }
        $ip_info{IP}{$this_ip}{MAJOR_FREQ} = $maj_freq;
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ});
            push(@{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} }, $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{$maj_freq}{BOOT_TIME});
        }
        my $maj_span = max(@{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} }) - min(@{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} });
        if($maj_span > 3) {
            $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} = 1;
        }
        else {
            $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} = 0;
        }
    }
    else {
        $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} = 0;
    }
}


#####
## Boot Time based Freq Heuristics
print STDERR "start to run Boot Time based Freq Heuristics..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists($ip_info{IP}{$this_ip}{CONN}));
    
    next if(!exists($ip_info{IP}{$this_ip}{BOOT_TIME_FREQ}));
    next if(scalar(@{ $ip_info{IP}{$this_ip}{BOOT_TIME_FREQ} }) < $FLOW_THRESHOLD);
    my @tmp = @{ $ip_info{IP}{$this_ip}{BOOT_TIME_FREQ} };
    my $boo_time_freq_stdev = MyUtil::stdev(\@tmp);
    if($boo_time_freq_stdev > $FREQ_THRESHOLD) {
        $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_FREQ} = 1;
    }
    else {
        $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_FREQ} = 0;
    }
}


#####
## TTL Heuristics
print STDERR "start to run TTL Heuristics..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    
    next if(!exists($ip_info{IP}{$this_ip}{TTL}));

    ## number of TTLs
    if(scalar(keys %{ $ip_info{IP}{$this_ip}{TTL} }) > 1) {
        $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} = 1;
    }
    else {
        $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} = 0;
    }

    ## TTLs difference
    my @tmp = (keys %{ $ip_info{IP}{$this_ip}{TTL} });
    $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_DIFF} = 0;
    foreach my $ind1 (0 .. scalar(@tmp)-1) {
        foreach my $ind2 ($ind1+1 .. scalar(@tmp)-1) {
            if(abs($tmp[$ind1] - $tmp[$ind2]) == 1) {
                $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_DIFF} = 1;
                last;
            }
            last if($ip_info{IP}{$this_ip}{DETECTED_BY_TTL_DIFF} == 1);
        }
    }

    ## TTLs majority: 63, 127
    $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} = 0;
    foreach my $ind1 (0 .. scalar(@tmp)-1) {
        if($tmp[$ind1] != 63 and $tmp[$ind1] != 127) {
            $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} = 1;
            last;
        }
    }
}




#####
## statistics
if($STATISTICS1) {
    my $num_ip_no_UA_no_TS            = 0;   ## num of IPs with "no User Agent" && "no TCP Timestamp"
    my $num_ip_no_UA_no_stable_f      = 0;   ## num of IPs with "no User Agent" && "no stable freq"
    my $num_ip_no_UA_w_stable_f       = 0;   ## num of IPs with "no User Agent" && "with stable freq"
    my $num_ip_no_UA_w_true_stable_f  = 0;   ## num of IPs with "no User Agent" && "with stable freq detect"
    my $num_ip_no_UA_w_false_stable_f = 0;   ## num of IPs with "no User Agent" && "with stable freq not detect"
    my $num_ip_true_UA_no_TS          = 0;   ## num of IPs with "User Agent detect" && "no TCP Timestamp"
    my $num_ip_false_UA_no_TS         = 0;   ## num of IPs with "User Agent does not detect" && "no TCP Timestamp"
    my $num_ip_true_UA_no_stable_f    = 0;   ## num of IPs with "User Agent detect" && "no stable freq"
    my $num_ip_false_UA_no_stable_f   = 0;   ## num of IPs with "User Agent does not detect" && "no stable freq"
    my $num_ip_true_UA_w_stable_f     = 0;   ## num of IPs with "User Agent detect" && "with stable freq"
    my $num_ip_false_UA_w_stable_f    = 0;   ## num of IPs with "User Agent does not detect" && "with stable freq"

    my $num_ip_TT = 0;
    my $num_ip_TF = 0;  ## UA say YES, but Freq say NO
    my $num_ip_FT = 0;  ## UA say NO , but Freq say YES
    my $num_ip_FF = 0;
    my $num_ip_TF_miss_freq = 0;  ## in the case of TF, it's due to some OS/Devices don't have stable freq
    my $num_ip_FT_miss_UA = 0;    ## in the case of FT, it's due to some flows with stable freq don't have UA

    my $num_ip_new_TT = 0;
    my $num_ip_new_TF = 0;  ## UA say YES, but Freq say NO
    my $num_ip_new_FT = 0;  ## UA say NO , but Freq say YES
    my $num_ip_new_FF = 0;

    foreach my $this_ip (keys %{ $ip_info{IP} }) {
        if(!exists $ip_info{IP}{$this_ip}{CONN}) {
            $num_ip_no_UA_no_TS ++;
            next;
        }

        print "$this_ip:\n" if($DEBUG3);

        #####
        ## IP level
        if(!exists $ip_info{IP}{$this_ip}{DETECTED_BY_UA}) {
            print "  - UA: none\n" if($DEBUG3);
            print "  - OS: none\n" if($DEBUG3);
            print "  - Devices: none\n" if($DEBUG3);
            print "  - freq: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{STABLE_FREQ}) {
                $num_ip_no_UA_no_stable_f ++;
                print "no stable\n" if($DEBUG3);
            }
            else {
                $num_ip_no_UA_w_stable_f ++;
                if($ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                    $num_ip_no_UA_w_true_stable_f ++;
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                    $num_ip_no_UA_w_false_stable_f ++;
                }
                print "    - ".join(", ", @{ $ip_info{IP}{$this_ip}{STABLE_FREQ} })."\n" if($DEBUG3);
            }

            print "  - boot time: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME}) {
                print "no boot time\n" if($DEBUG3);
            }
            else {
                if($ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                }
                print "    - ".join(", ", @{ $ip_info{IP}{$this_ip}{BOOT_TIME} })."\n" if($DEBUG4);
                print "      stdev=".(MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }))."\n" if($DEBUG4);
            }

            print "  - boot time using major freq: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ}) {
                print "no boot time\n" if($DEBUG3);
            }
            else {
                if($ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                }
                print "    - (".$ip_info{IP}{$this_ip}{MAJOR_FREQ}."): ".join(", ", @{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} })."\n" if($DEBUG4);
                print "      span=".(max(@{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} }) - min(@{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} }))."\n" if($DEBUG4);
            }

            print "  - boot time based freq: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_FREQ}) {
                print "no boot time freq\n" if($DEBUG3);
            }
            else {
                if($ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_FREQ} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                }
                print "    - ".join(", ", (@{ $ip_info{IP}{$this_ip}{BOOT_TIME_FREQ} }))."\n" if($DEBUG4);
                print "      stdev=".(MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{BOOT_TIME_FREQ} }))."\n" if($DEBUG4);
            }

        }
        ## else: DETECTED_BY_UA exists
        else {  
            print "  - UA: " if($DEBUG3);
            if($ip_info{IP}{$this_ip}{DETECTED_BY_UA} == 1) {
                print "Yes!!!\n" if($DEBUG3);
            }
            else {
                print "No!!!\n" if($DEBUG3);
            }
            print "  - OS: " if($DEBUG3);
            foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                print "$this_os, " if($DEBUG3);
            }
            print "\n  - Devices: " if($DEBUG3);
            foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) {
                print "$this_device, " if($DEBUG3);
            }
            print "\n" if($DEBUG3);

            print "  - freq: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{TIMESTAMP_EXIST}) {
                print "none\n" if($DEBUG3);

                if($ip_info{IP}{$this_ip}{DETECTED_BY_UA} == 1) {
                    $num_ip_true_UA_no_TS ++;
                }
                else {
                    $num_ip_false_UA_no_TS ++;
                }
            }
            elsif(!exists $ip_info{IP}{$this_ip}{STABLE_FREQ}) {
                print " no stable\n" if($DEBUG3);

                if($ip_info{IP}{$this_ip}{DETECTED_BY_UA} == 1) {
                    $num_ip_true_UA_no_stable_f ++;
                }
                else {
                    $num_ip_false_UA_no_stable_f ++;
                }
            }
            else {
                if($ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                }

                if($ip_info{IP}{$this_ip}{DETECTED_BY_UA} == 1) {
                    $num_ip_true_UA_w_stable_f ++;
                }
                else {
                    $num_ip_false_UA_w_stable_f ++;
                }

                print "    - ".join(", ", @{ $ip_info{IP}{$this_ip}{STABLE_FREQ} })."\n" if($DEBUG3);


                ############
                ## evaluate two methods
                if($ip_info{IP}{$this_ip}{DETECTED_BY_UA}   == 1 and 
                   ($ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} == 1 or 
                    (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} and 
                    $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} == 1)
                   ) ) {
                    print "  => Truth Positive\n" if($DEBUG3);
                    $num_ip_TT ++;

                    if( (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} == 1) or
                        (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} == 1) or
                        (exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} == 1) or
                        (exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} == 1) ) {
                        
                        $num_ip_new_TT ++;
                    }
                    else {
                        $num_ip_new_TF ++;

                        ## analyze the reason
                        ## a) devices with diff UA have the same freq
                        ## b) devices with diff UA do not have stable freq
                        my $num_os_without_freq = scalar(keys %{ $ip_info{IP}{$this_ip}{OS} });
                        my $num_device_without_freq = scalar(keys %{ $ip_info{IP}{$this_ip}{DEVICE} });
                        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
                            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
                                foreach my $this_agent (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {
                                    foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                                        if($this_agent =~ /$this_os/) {
                                            ## this connection belongs to this OS
                                            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}) {
                                                if(!exists $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ}) {
                                                    $num_os_without_freq --;
                                                }
                                                push(@{ $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ} }, $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ});
                                            }
                                        }
                                    }

                                    foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) {
                                        if($this_agent =~ /$this_device/) {
                                            ## this connection belongs to this Device
                                            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}) {
                                                if(!exists $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ}) {
                                                    $num_device_without_freq --;
                                                }
                                                push(@{ $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ} }, $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ});
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if(scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) > 0 and
                           $num_os_without_freq > 0) {
                            $num_ip_TF_miss_freq ++;
                        }
                        elsif(scalar(keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) > 0 and
                              $num_device_without_freq > 0) {
                            $num_ip_TF_miss_freq ++;
                        }
                        print "--------------------------\n" if($DEBUG3);
                        print "     - OS:\n" if($DEBUG3);
                        foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                            if(!exists $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ}) {
                                print "         - $this_os: none\n" if($DEBUG3);
                            }
                            else {
                                print "         - $this_os: ".join(", ", @{ $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ} })."\n" if($DEBUG3);
                            }
                        }
                        print "     - Device:\n" if($DEBUG3);
                        foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) {
                            if(!exists $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ}) {
                                print "         - $this_device: none\n" if($DEBUG3);
                            }
                            else {
                                print "         - $this_device: ".join(", ", @{ $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ} })."\n" if($DEBUG3);
                            }
                        }
                        print "--------------------------\n" if($DEBUG3);
                    }
                    
                }
                elsif($ip_info{IP}{$this_ip}{DETECTED_BY_UA}   == 0 and 
                      $ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} == 0) {
                    print "  => Truth Negative\n" if($DEBUG3);
                    $num_ip_FF ++;
                    $num_ip_new_FF ++;
                }
                elsif($ip_info{IP}{$this_ip}{DETECTED_BY_UA}   == 1 and 
                      $ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} == 0) {
                    print "  => False Negative (UA say YES but Freq say NO)\n" if($DEBUG3);
                    $num_ip_TF ++;
                    $num_ip_new_TF ++;


                    # if( (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} and 
                    #      $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} == 1) or 
                    #     (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} and 
                    #      $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} == 1) or
                    #     (exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} and 
                    #      $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} == 1) or
                    #     (exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} and 
                    #      $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} == 1) {
                        
                    # }

                    ## analyze the reason
                    ## a) devices with diff UA have the same freq
                    ## b) devices with diff UA do not have stable freq
                    my $num_os_without_freq = scalar(keys %{ $ip_info{IP}{$this_ip}{OS} });
                    my $num_device_without_freq = scalar(keys %{ $ip_info{IP}{$this_ip}{DEVICE} });
                    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
                        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
                            foreach my $this_agent (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {
                                foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                                    if($this_agent =~ /$this_os/) {
                                        ## this connection belongs to this OS
                                        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}) {
                                            if(!exists $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ}) {
                                                $num_os_without_freq --;
                                            }
                                            push(@{ $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ} }, $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ});
                                        }
                                    }
                                }

                                foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) {
                                    if($this_agent =~ /$this_device/) {
                                        ## this connection belongs to this Device
                                        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}) {
                                            if(!exists $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ}) {
                                                $num_device_without_freq --;
                                            }
                                            push(@{ $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ} }, $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ});
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if(scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) > 0 and
                       $num_os_without_freq > 0) {
                        $num_ip_TF_miss_freq ++;
                    }
                    elsif(scalar(keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) > 0 and
                          $num_device_without_freq > 0) {
                        $num_ip_TF_miss_freq ++;
                    }
                    print "--------------------------\n" if($DEBUG3);
                    print "     - OS:\n" if($DEBUG3);
                    foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                        if(!exists $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ}) {
                            print "         - $this_os: none\n" if($DEBUG3);
                        }
                        else {
                            print "         - $this_os: ".join(", ", @{ $ip_info{IP}{$this_ip}{OS2}{$this_os}{STABLE_FREQ} })."\n" if($DEBUG3);
                        }
                    }
                    print "     - Device:\n" if($DEBUG3);
                    foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) {
                        if(!exists $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ}) {
                            print "         - $this_device: none\n" if($DEBUG3);
                        }
                        else {
                            print "         - $this_device: ".join(", ", @{ $ip_info{IP}{$this_ip}{DEVICE2}{$this_device}{STABLE_FREQ} })."\n" if($DEBUG3);
                        }
                    }
                    print "--------------------------\n" if($DEBUG3);
                }
                elsif($ip_info{IP}{$this_ip}{DETECTED_BY_UA}   == 0 and 
                      ($ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} == 1 or 
                       (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} and 
                       $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} == 1)
                      ) ) {
                    print "  => False Positive (UA say NO but Freq say YES)\n" if($DEBUG3);
                    # my $stdev_freq_of_ip = MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{STABLE_FREQ} });
                    # print "    stdev=$stdev_freq_of_ip\n" if($DEBUG3);
                    $num_ip_FT ++;

                    if( (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} == 1) or
                        (exists $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} == 1) or
                        (exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} == 1) or
                        (exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} and 
                         $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} == 1) ) {
                        
                        $num_ip_new_FT ++;


                        ## analyze the reason
                        ## a) devices with diff freq have the same UA
                        ## b) devices with diff freq do not have UA
                        my $num_freq_without_UA = 0;
                        my $num_ttl_without_UA = 0;
                        if(exists $ip_info{IP}{$this_ip}{TTL}) {
                            $num_ttl_without_UA = scalar(keys %{ $ip_info{IP}{$this_ip}{TTL} });
                        }
                        my %ttls = ();
                        print "--------------------------\n" if($DEBUG3);
                        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
                            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}) {
                                print "     - freq: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}."\n" if($DEBUG3);
                                if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
                                    $num_freq_without_UA ++;
                                }
                                else {
                                    print "         - UA: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) )."\n" if($DEBUG3);
                                }
                            }

                            next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL});
                            foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
                                next if(exists $ttls{$this_ttl});
                                $ttls{$this_ttl} = 1;
                                $num_ttl_without_UA --;
                            }
                        }
                        if($num_freq_without_UA > 0 and $ip_info{IP}{$this_ip}{DETECTED_BY_FREQ} == 1) {
                            $num_ip_FT_miss_UA ++;
                            print "     $num_freq_without_UA UA missing.\n" if($DEBUG3);
                        }
                        elsif($num_ttl_without_UA != 0 and 
                           (exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} and 
                            $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} == 1) ) {
                            
                            $num_ip_FT_miss_UA ++;
                            print "     $num_freq_without_UA UA missing.\n" if($DEBUG3);
                        }
                        print "--------------------------\n" if($DEBUG3);
                    }
                    else {
                        $num_ip_new_FF ++;
                    }

                }
                else {
                    die "should not be here\n";
                }
            }

            print "  - boot time: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME}) {
                print "no boot time\n" if($DEBUG3);
            }
            else {
                if($ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                }
                print "    - ".join(", ", @{ $ip_info{IP}{$this_ip}{BOOT_TIME} })."\n" if($DEBUG4);
                print "      stdev=".(MyUtil::stdev(\@{ $ip_info{IP}{$this_ip}{BOOT_TIME} }))."\n" if($DEBUG4);
            }

            print "  - boot time using major freq: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ}) {
                print "no boot time\n" if($DEBUG3);
            }
            else {
                if($ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_SAME_FREQ} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                }
                print "    - (".$ip_info{IP}{$this_ip}{MAJOR_FREQ}."): ".join(", ", @{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} })."\n" if($DEBUG4);
                print "      ".(max(@{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} }) - min(@{ $ip_info{IP}{$this_ip}{MAJOR_BOOT_TIME} }))."\n" if($DEBUG4);
            }

            print "  - boot time based freq: " if($DEBUG3);
            if(!exists $ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_FREQ}) {
                print "no boot time freq\n" if($DEBUG3);
            }
            else {
                if($ip_info{IP}{$this_ip}{DETECTED_BY_BOOT_TIME_FREQ} == 1) {
                    print "Yes!!!\n" if($DEBUG3);
                }
                else {
                    print "No!!!\n" if($DEBUG3);
                }
                my @tmp = @{ $ip_info{IP}{$this_ip}{BOOT_TIME_FREQ} };
                print "    - ".join(", ", (@tmp))."\n" if($DEBUG4);
                print "      ".(MyUtil::stdev(\@tmp))."\n" if($DEBUG4);
            }
        }

        if(!exists $ip_info{IP}{$this_ip}{TTL}) {
            print "  - TTL: none\n";
        }
        else {
            print "  - TTL NUM: ";
            if($ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} == 1) {
                print "Yes!!!\n" if($DEBUG3);
            }
            else {
                print "No!!!\n" if($DEBUG3);
            }

            print "  - TTL DIFF: ";
            if($ip_info{IP}{$this_ip}{DETECTED_BY_TTL_DIFF} == 1) {
                print "Yes!!!\n" if($DEBUG3);
            }
            else {
                print "No!!!\n" if($DEBUG3);
            }

            print "  - TTL MAJORITY: ";
            if($ip_info{IP}{$this_ip}{DETECTED_BY_TTL_MAJORITY} == 1) {
                print "Yes!!!\n" if($DEBUG3);
            }
            else {
                print "No!!!\n" if($DEBUG3);
            }
            print "    - ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{TTL} }))."\n" if($DEBUG3);
        }

        print "  - TCP WIN: ";
        if(!exists $ip_info{IP}{$this_ip}{TTL}) {
            print "none\n" if($DEBUG3);
        }
        else {
            # if($ip_info{IP}{$this_ip}{DETECTED_BY_TTL_NUM} == 1) {
            #     print "Yes!!!\n" if($DEBUG3);
            # }
            # else {
            #     print "No!!!\n" if($DEBUG3);
            # }
            print "\n" if($DEBUG3);
            print "    - ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{WIN} }))."\n" if($DEBUG3);
        }


        #####
        ## Connection level
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            print "  -> $this_conn " if($DEBUG3);

            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}) {
                my $this_num_pkt = scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} });
                my $this_duration = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[-1] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[0];
                print "(# TS: pkt=$this_num_pkt, time=$this_duration) " if($DEBUG3);
            }
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
                my $this_num_pkt = scalar(keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} });
                print "(# UA: $this_num_pkt)" if($DEBUG3);
            }
            print "\n" if($DEBUG3);

            ## User Agent
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {

                print "    - User Agents:\n" if($DEBUG3);
                foreach my $this_agent (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {
                    print "      - $this_agent\n" if($DEBUG3);
                }
                print "    - OS: " if($DEBUG3);
                foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} }) {
                    print "$this_os, " if($DEBUG3);
                }
                print "\n    - Devices: " if($DEBUG3);
                foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} }) {
                    print "$this_device, " if($DEBUG3);
                }
                print "\n" if($DEBUG3);

            }

            ## Stable frequency
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}) {
                print "    - stable freq: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{STABLE_FREQ}."\n" if($DEBUG3);
                print "    - freq: ".join(", ", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} })."\n" if($DEBUG4);
            }
            elsif(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS}) {
                print "    - stable freq: none\n" if($DEBUG3);
                print "    - freq: ".join(", ", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQS} })."\n" if($DEBUG4);
            }
            else {
                print "    - freq: none\n" if($DEBUG3);
            }

            ## boot time
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME}) {
                print "    - boot time: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME}."\n" if($DEBUG3);
                print "    - boot time freq: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME_FREQ}."\n" if($DEBUG3);
                # print "\n------------------------------------\n" if($DEBUG3);
                print "    - boot time 2: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{2}{BOOT_TIME}."\n" if($DEBUG3);
                print "    - boot time 10: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{10}{BOOT_TIME}."\n" if($DEBUG3);
                print "    - boot time 100: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{100}{BOOT_TIME}."\n" if($DEBUG3);
                print "    - boot time 128: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{128}{BOOT_TIME}."\n" if($DEBUG3);
                print "    - boot time 200: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{200}{BOOT_TIME}."\n" if($DEBUG3);
                print "    - boot time 1000: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{TEST_FREQ}{1000}{BOOT_TIME}."\n" if($DEBUG3);
                print join(", ", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} })."\n" if($DEBUG4);
                print join(", ", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} })."\n" if($DEBUG4);
                # print "------------------------------------\n\n" if($DEBUG3);
            }

            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
                print "    - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }))."\n" if($DEBUG3);

                # if(scalar(keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) > 1) {
                #     die "There are multiple TTL in one connection\n";
                # }
            }

            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN}) {
                print "    - TCP WIN: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN} }))."\n" if($DEBUG3);
            }
        }
    }
    if($DEBUG3) {
        print "num of IPs with no User Agent && no TCP Timestamp: $num_ip_no_UA_no_TS\n";
        print "num of IPs with no User Agent && no stable freq: $num_ip_no_UA_no_stable_f\n";
        print "num of IPs with no User Agent && with stable freq: $num_ip_no_UA_w_stable_f\n";
        print "num of IPs with no User Agent && with stable freq detect: $num_ip_no_UA_w_true_stable_f\n";
        print "num of IPs with no User Agent && with stable freq not detect: $num_ip_no_UA_w_false_stable_f\n";
        print "num of IPs with User Agent detect && no TCP Timestamp: $num_ip_true_UA_no_TS\n";
        print "num of IPs with User Agent does not detect && no TCP Timestamp: $num_ip_false_UA_no_TS\n";
        print "num of IPs with User Agent detect && no stable freq: $num_ip_true_UA_no_stable_f\n";
        print "num of IPs with User Agent does not detect && no stable freq: $num_ip_false_UA_no_stable_f\n";
        print "num of IPs with User Agent detect && with stable freq: $num_ip_true_UA_w_stable_f\n";
        print "num of IPs with User Agent does not detect && with stable freq: $num_ip_false_UA_w_stable_f\n";
        print "num of IPs with User Agent say YES && Freq say YES: $num_ip_TT\n";
        print "num of IPs with User Agent say NO && Freq say NO: $num_ip_FF\n";
        print "num of IPs with User Agent say YES && Freq say NO: $num_ip_TF\n";
        print "num of IPs with User Agent say YES && Freq say NO is due to miss freq: $num_ip_TF_miss_freq\n";
        print "num of IPs with User Agent say NO && Freq say YES: $num_ip_FT\n";
        print "num of IPs with User Agent say NO && Freq say YES is due to miss UA: $num_ip_FT_miss_UA\n";
        print "new TT: $num_ip_new_TT\n";
        print "new FF: $num_ip_new_FF\n";
        print "new TF: $num_ip_new_TF\n";
        print "new FT: $num_ip_new_FT\n";
        print "======================================================================\n";
    }
    open FH, ">> $output_dir/statistics1.$file_name.txt" or dir $!;
    open FH_ALL, ">> $output_dir/statistics1.txt" or dir $!;
    print FH join(", ", ($num_ip_no_UA_no_TS, $num_ip_no_UA_no_stable_f, 
        $num_ip_no_UA_w_stable_f, $num_ip_no_UA_w_true_stable_f, $num_ip_no_UA_w_false_stable_f, 
        $num_ip_true_UA_no_TS, $num_ip_false_UA_no_TS, 
        $num_ip_true_UA_no_stable_f, $num_ip_false_UA_no_stable_f, 
        $num_ip_true_UA_w_stable_f, $num_ip_false_UA_w_stable_f, 
        $num_ip_TT, $num_ip_TF, $num_ip_FT, $num_ip_FF, 
        $num_ip_TF - $num_ip_TF_miss_freq, $num_ip_TF_miss_freq, 
        $num_ip_FT - $num_ip_FT_miss_UA, $num_ip_FT_miss_UA, 
        $num_ip_new_TT, $num_ip_new_FF, $num_ip_new_TF, $num_ip_new_FT, 
        $num_ip_new_TF - $num_ip_TF_miss_freq, $num_ip_new_FT - $num_ip_FT_miss_UA ))."\n";
    print FH_ALL join(", ", ($num_ip_no_UA_no_TS, $num_ip_no_UA_no_stable_f, 
        $num_ip_no_UA_w_stable_f, $num_ip_no_UA_w_true_stable_f, $num_ip_no_UA_w_false_stable_f, 
        $num_ip_true_UA_no_TS, $num_ip_false_UA_no_TS, 
        $num_ip_true_UA_no_stable_f, $num_ip_false_UA_no_stable_f, 
        $num_ip_true_UA_w_stable_f, $num_ip_false_UA_w_stable_f, 
        $num_ip_TT, $num_ip_TF, $num_ip_FT, $num_ip_FF, 
        $num_ip_TF - $num_ip_TF_miss_freq, $num_ip_TF_miss_freq, 
        $num_ip_FT - $num_ip_FT_miss_UA, $num_ip_FT_miss_UA, 
        $num_ip_new_TT, $num_ip_new_FF, $num_ip_new_TF, $num_ip_new_FT, 
        $num_ip_new_TF - $num_ip_TF_miss_freq, $num_ip_new_FT - $num_ip_FT_miss_UA ))."\n";
    close FH;
    close FH_ALL;
}



if($STATISTICS2) {
    ## has User Agent but no TCP Timestamp ==> Windows machine??
    my $doubt_cnt = 0;
    my $has_windows_cnt = 0;
    my $has_other_os_cnt = 0;
    my $has_both_os_cnt = 0;
    my $no_os_cnt = 0;

    foreach my $this_ip (keys %{ $ip_info{IP} }) {
        if(exists $ip_info{IP}{$this_ip}{OS} and 
           !exists $ip_info{IP}{$this_ip}{TIMESTAMP_EXIST}) {
            $doubt_cnt ++;

            my $has_windows = 0;
            my $has_others = 0;
            foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                if($this_os =~ /Windows/i) {
                    $has_windows = 1;
                }
                else {
                    $has_others = 1;
                    print "$this_ip: $this_os\n" if($DEBUG3);
                }
            }
            if($has_windows == 1) {
                $has_windows_cnt ++;
            }
            if($has_windows == 1 and $has_others == 1) {
                $has_both_os_cnt ++;
            }
            if($has_windows == 0 and $has_others == 1) {
                $has_other_os_cnt ++;
            }
            if($has_windows == 0 and $has_others == 0) {
                $no_os_cnt ++;
            }
            
        }
    }

    if($DEBUG3) {
        print "$has_windows_cnt / $ doubt_cnt IPs which do not have TCP TS have windows keyword in UA\n";
        print "$has_other_os_cnt / $ doubt_cnt IPs which do not have TCP TS have other (but no windows) keyword in UA\n";
        print "$has_both_os_cnt / $ doubt_cnt IPs which do not have TCP TS have windows & other keyword in UA\n";
        print "$no_os_cnt / $ doubt_cnt IPs which do not have TCP TS do not have any OS keyword in UA\n";
        print "======================================================================\n";
    }

    open FH, ">> $output_dir/statistics2.$file_name.txt" or dir $!;
    open FH_ALL, ">> $output_dir/statistics2.txt" or dir $!;
    print FH join(", ", ($doubt_cnt, $has_windows_cnt, $has_other_os_cnt, $has_both_os_cnt, $no_os_cnt))."\n";
    print FH_ALL join(", ", ($doubt_cnt, $has_windows_cnt, $has_other_os_cnt, $has_both_os_cnt, $no_os_cnt))."\n";
    close FH;
    close FH_ALL;
}














