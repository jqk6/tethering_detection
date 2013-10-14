#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/09/25 @ Narus
##
## Compare the result of TTL and boot time heuristic
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
##      perl boot_time_vs_ttl_freq.pl 49
##      perl boot_time_vs_ttl_freq.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
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
my $BOOT_TIME_INTERVAL_THRESHOLD = 3;  ## the boot time interval between two devices should be larger than this threshold
my $BOOT_TIME_SPAN_THRESHOLD = 1;  ## the boot time interval between packets should be smaller than this threshold
my $FLOW_PKT_NUM_THRESHOLD = 0;
my $FLOW_DURATION_THRESHOLD = 0;

my @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);


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
    $BOOT_TIME_INTERVAL_THRESHOLD = 1;
    $BOOT_TIME_SPAN_THRESHOLD = 1;
    $FLOW_PKT_NUM_THRESHOLD = 10;
    $FLOW_DURATION_THRESHOLD = 5;
    @CLOCK_FREQ = (100, 128, 200, 250, 1000);
}
elsif($iteration == 1) {
    ## for mawi
    $FIX_SRC       = 0;
    $input_dir_timestamp  = "/data/ychen/mawi/text5";
    $file_name_ts = "$input_dir_timestamp/$file_name";
    

    $BOOT_TIME_FREQ = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 1;
    $BOOT_TIME_SPAN_THRESHOLD = 1;
    $FLOW_PKT_NUM_THRESHOLD = 50;
    $FLOW_DURATION_THRESHOLD = 0;
    @CLOCK_FREQ = (100, 128, 200, 250, 1000);
}
##==================================================
else {
    die "wrong iter: $iteration\n";
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
    $ip_info{IP}{$src}{ALL_FLOW}{RX_TIME}{$time + $time_usec / 1000000}{TX_TIME} = $tcp_ts_val;
    $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;
}
close FH;



############################################################
## Calculate boot time
############################################################
print STDERR "start to Calculate boot time and identify OS..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    ## Flow:
    ##   IP - Flow |- TX_TIME (o)
    ##             |- RX_TIME (o)
    ##             |- BOOT_TIME
    ##             |- FREQ
    ##             |- FREQ
    ##             |- TTL (o)
    ##
    ## Boot Time:
    ##   IP - GROUP_BOOT_TIME - FLOW |- TX_TIME
    ##                               |- RX_TIME
    ##                               |- BOOT_TIME
    ##                               |- FREQ
    ##                               |- FREQ
    ##                               |- TTL
    ##
    ## Frequency:
    ##   IP - FREQ - FLOW |- TX_TIME
    ##                    |- RX_TIME
    ##                    |- BOOT_TIME
    ##                    |- FREQ
    ##                    |- TTL
    ##
    ## TTL:
    ##   IP - TTL - FLOW |- TX_TIME
    ##                   |- RX_TIME
    ##                   |- BOOT_TIME
    ##                   |- FREQ
    ##                   |- FREQ
    ##
    print "------------------------------\n" if($DEBUG3);
    if(exists($ip_info{IP}{$this_ip}{CONN})) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            print "$this_ip -- $this_conn: \n" if($DEBUG3);

            ## TTL of the flow
            my %ttl = ();
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
                print "  - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }))."\n" if($DEBUG3);

                foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
                    $ttl{$this_ttl} = 1;
                    
                    $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn} = () if(!exists $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn});
                }
            }

            ## Boot time and frequency1 of the flow
            my ($freq, $boot_time);
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
                next if($freq <= 0);
                
                print "  - boot time: $boot_time\n" if($DEBUG3 and $freq > 0);
                print "  - freq: $freq\n" if($DEBUG3 and $freq > 0);
                
                ## Flow
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                
                ## TTL
                foreach my $this_ttl (keys %ttl) {
                    @{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                    @{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                    $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                    $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                }

                ## Frequency
                if($freq > 0) {
                    @{ $ip_info{IP}{$this_ip}{FREQ}{$freq}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                    @{ $ip_info{IP}{$this_ip}{FREQ}{$freq}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                    $ip_info{IP}{$this_ip}{FREQ}{$freq}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                    foreach my $this_ttl (keys %ttl) {
                        $ip_info{IP}{$this_ip}{FREQ}{$freq}{CONN}{$this_conn}{TTL}{$this_ttl} = 1;
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
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME} = $boot_time;
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ} = $freq;
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
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{BOOT_TIME} = $boot_time;
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{FREQ} = $freq;
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
##             |- TTL (o)
##
## Boot Time:
##   IP - GROUP_BOOT_TIME - FLOW |- TX_TIME
##                               |- RX_TIME
##                               |- BOOT_TIME
##                               |- FREQ
##                               |- TTL
## Frequency:
##   IP - FREQ - FLOW |- TX_TIME
##                    |- RX_TIME
##                    |- BOOT_TIME
##                    |- TTL
##
## TTL:
##   IP - TTL - FLOW |- TX_TIME
##                   |- RX_TIME
##                   |- BOOT_TIME
##                   |- FREQ
##
print STDERR "start to Evaluate results..\n" if($DEBUG2);
my $cnt_ip = 0;
my $tp_ttl = 0;
my $tn_ttl = 0;
my $fp_ttl = 0;
my $fn_ttl = 0;
my $tp_freq = 0;
my $tn_freq = 0;
my $fp_freq = 0;
my $fn_freq = 0;
my $tp_boot = 0;
my $tn_boot = 0;
my $fp_boot = 0;
my $fn_boot = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME});
    print "==============================\n";
    print "$this_ip\n";


    ## if the Timestamp keeps increasing
    my $pre_rx_time = -1;
    my $pre_tx_time = -1;
    my $if_dec = 0;
    my $num_dec_threshold = 1;
    foreach my $this_rx (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{RX_TIME} }) ) {
        next if($this_rx == $pre_rx_time);

        my $this_tx = $ip_info{IP}{$this_ip}{RX_TIME}{$this_rx}{TX_TIME};

        ## check if the Timestamp becomes smaller
        # if($this_tx <= $pre_tx_time and ($pre_tx_time - $this_tx) <= 400000000) {
        if($this_tx <= $pre_tx_time) {
            $if_dec ++;
            
            last if($if_dec >= $num_dec_threshold);
        }
    }

    ## Freq
    my $num_freq = scalar(keys %{ $ip_info{IP}{$this_ip}{FREQ} });

    ## Boot time
    my $num_boot_time = scalar(keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME} });
    
    ## TTL
    my %ttls = ();
    foreach my $this_freq (keys %{ $ip_info{IP}{$this_ip}{FREQ} }) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{FREQ}{$this_freq}{CONN} }) {
            foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{FREQ}{$this_freq}{CONN}{$this_conn}{TTL} }) {
                if(abs($this_ttl - 63) < 5) {
                    $ttls{63} = 1;
                }
                elsif(abs($this_ttl - 127) < 5) {
                    $ttls{127} = 1;
                }
                else {
                    $ttls{$this_ttl} = 1;
                }
            }
        }
    }
    my $num_ttl = scalar(keys %ttls);
    

    ##################
    ## Strat to check correctness
    ##################
    if($if_dec >= $num_dec_threshold) {
        $cnt_ip ++;

        ## TTL heuristics
        if($num_ttl >= 2) {
            print "TTL: True Positive\n";
            $tp_ttl ++;
        }
        else {
            print "TTL False Negative\n";
            $fn_ttl ++;
        }

        ## Freq heuristics
        if($num_freq >= 2) {
            print "Freq: True Positive\n";
            $tp_freq ++;
        }
        else {
            print "Freq: False Negative\n";
            $fn_freq ++;
        }

        ## Boot time
        if($num_boot_time >= 2) {
            print "Boot Time: True Positive\n";
            $tp_boot ++;
        }
        else {
            print "Boot Time: False Negative\n";
            $fn_boot ++;
        }
    }
    elsif($if_dec < $num_dec_threshold) {
        $cnt_ip ++;

        ## TTL heuristics
        if($num_ttl >= 2) {
            print "TTL: False Positive\n";
            $fp_ttl ++;
        }
        else {
            print "TTL True Negative\n";
            $tn_ttl ++;
        }

        ## Freq heuristics
        if($num_freq >= 2) {
            print "Freq: False Positive\n";
            $fp_freq ++;
        }
        else {
            print "Freq: True Negative\n";
            $tn_freq ++;
        }

        ## Boot time
        if($num_boot_time >= 2) {
            print "Boot Time: False Positive\n";
            $fp_boot ++;
        }
        else {
            print "Boot Time: True Negative\n";
            $tn_boot ++;
        }
    }
    else {
        die "should not be here: num decreasing=$if_dec\n";
    }

    # if($num_boot_time >= 2) {
    #     $cnt_ip ++;

    #     ## TTL heuristics
    #     if($num_ttl >= 2) {
    #         print "TTL: True Positive\n";
    #         $tp_ttl ++;
    #     }
    #     else {
    #         print "TTL False Negative\n";
    #         $fn_ttl ++;
    #     }

    #     ## Freq heuristics
    #     if($num_freq >= 2) {
    #         print "Freq: True Positive\n";
    #         $tp_freq ++;
    #     }
    #     else {
    #         print "Freq: False Negative\n";
    #         $fn_freq ++;
    #     }
    # }
    # elsif($num_boot_time == 1) {
    #     $cnt_ip ++;

    #     ## TTL heuristics
    #     if($num_ttl >= 2) {
    #         print "TTL: False Positive\n";
    #         $fp_ttl ++;
    #     }
    #     else {
    #         print "TTL True Negative\n";
    #         $tn_ttl ++;
    #     }

    #     ## Freq heuristics
    #     if($num_freq >= 2) {
    #         print "Freq: False Positive\n";
    #         $fp_freq ++;
    #     }
    #     else {
    #         print "Freq: True Negative\n";
    #         $tn_freq ++;
    #     }
    # }
    # else {
    #     die "should not be here: # boot time=$num_boot_time\n";
    # }


    ####################
    ## DEBUG: print details
    ####################
    if($DEBUG4) {

        ## decreasing

        if($if_dec >= $num_dec_threshold) {
            print "\n";
            print "Timestamp decreases $if_dec times:\n";
            foreach my $this_rx (sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{RX_TIME} }) ) {
                next if($this_rx == $pre_rx_time);

                my $this_tx = $ip_info{IP}{$this_ip}{RX_TIME}{$this_rx}{TX_TIME};
                print "$this_tx, ";
            }
            print "\n";
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

                ## Boot time
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME}) {
                    print "    - BOOT_TIME: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME}."\n";
                    print "    - FREQ: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ}."\n";
                }

                ## TTL
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{TTL}) {
                    print "    - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{TTL} }) )."\n";
                }

                ## Freq
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ}) {
                    print "    - FREQ: ".$ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ}."\n";
                }
            }
        }
    } ## End DEBUG print details
} ## end for all IPs


############################################################
## Output
############################################################
print "\nTTL[tp, tn, fp, fn], Freq[tp, tn, fp, fn], Boot[tp, tn, fp, fn]\n";
print "$cnt_ip\n";
print "TTL[$tp_ttl, $tn_ttl, $fp_ttl, $fn_ttl]\n";
print "Freq[$tp_freq, $tn_freq, $fp_freq, $fn_freq]\n";
print "Boot[$tp_boot, $tn_boot, $fp_boot, $fn_boot]\n";
print "\n";

open FH, ">> $output_dir/boot_time_vs_ttl_freq.$iteration.txt" or die $!;
print FH "$cnt_ip, $tp_ttl, $tn_ttl, $fp_ttl, $fn_ttl, $tp_freq, $tn_freq, $fp_freq, $fn_freq, $tp_boot, $tn_boot, $fp_boot, $fn_boot\n";
close FH;





1;

