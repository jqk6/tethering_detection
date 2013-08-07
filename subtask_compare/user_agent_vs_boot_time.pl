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
##      perl user_agent_boot_time.pl 49
##      perl user_agent_boot_time.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
##################################################

use strict;
use List::Util qw(sum max min);
use MyUtil;
use Tethering;

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


my $BOOT_TIME_INTERVAL_THRESHOLD = 3;  ## the boot time interval between two devices should be larger than this threshold

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
## Calculate boot time and identify OS
############################################################
print STDERR "start to Calculate boot time and identify OS..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    ## Flow:
    ##   IP - Flow |- TX_TIME
    ##             |- RX_TIME
    ##             |- BOOT_TIME
    ##             |- FREQ
    ##             |- User_Agent
    ##             |- OS
    ##
    ## Boot Time:
    ##   IP - GROUP_BOOT_TIME - FLOW |- TX_TIME
    ##                               |- RX_TIME
    ##                               |- BOOT_TIME
    ##                               |- FREQ
    ##                               |- User_Agent
    ##                               |- OS
    ##
    ## OS:
    ##   IP - OS - FLOW |- TX_TIME
    ##                  |- RX_TIME
    ##                  |- BOOT_TIME
    ##                  |- FREQ
    ##                  |- User_Agent
    ##
    print "------------------------------\n" if($DEBUG2);
    if(exists($ip_info{IP}{$this_ip}{CONN})) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            print "$this_ip -- $this_conn: \n" if($DEBUG2);

            ## OS of the flow
            my $os = "";
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
                my @tmp_user_agents = (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} });
                my @os = Tethering::identify_os(\@tmp_user_agents);
                die "one flow should just have one OS\n" if(scalar(@os) > 1);

                if(scalar(@os) == 1) {
                    $os = $os[0];
                    $ip_info{IP}{$this_ip}{OS}{$os} = ();
                }
                print "  - OS: $os\n" if($DEBUG2);
            }

            ## Boot time of the flow
            my ($freq, $boot_time);
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}) {
                ($freq, $boot_time) = Tethering::est_freq_boottime_enumeration1(
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }, 
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} });
                print "  - boot time: $boot_time\n" if($DEBUG2 and $freq > 0);
                print "  - freq: $freq\n" if($DEBUG2 and $freq > 0);

                ## OS
                if(!($os eq "")) {
                    @{ $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{TX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} };
                    @{ $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{RX_TIME} } = @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} };
                    %{ $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{AGENT} } = %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} };
                    $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                    $ip_info{IP}{$this_ip}{OS}{$os}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);
                }

                ## Flow
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} = $os if(!($os eq ""));
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{FREQ} = $freq if($freq > 0);
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{BOOT_TIME} = $boot_time if($freq > 0);

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
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{FREQ} = $freq;
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{BOOT_TIME} = $boot_time;
                                $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{OS} = $os if(!($os eq ""));

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
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{FREQ} = $freq;
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{BOOT_TIME} = $boot_time;
                        $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$boot_time}{CONN}{$this_conn}{OS} = $os if(!($os eq ""));
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
##   IP - Flow |- TX_TIME
##             |- RX_TIME
##             |- BOOT_TIME
##             |- FREQ
##             |- User_Agent
##             |- OS
##
## Boot Time:
##   IP - GROUP_BOOT_TIME - FLOW |- TX_TIME
##                               |- RX_TIME
##                               |- BOOT_TIME
##                               |- FREQ
##                               |- User_Agent
##                               |- OS
##
## OS:
##   IP - OS - FLOW |- TX_TIME
##                  |- RX_TIME
##                  |- BOOT_TIME
##                  |- FREQ
##                  |- User_Agent
##
print STDERR "start to Evaluate results..\n" if($DEBUG2);
my $cnt_ip = 0;
my $cnt_invalid_ip = 0;
my $tp = 0;
my $tn = 0;
my $fp = 0;
my $fn = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    my $num_os = 0;
    $num_os = scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) if(exists $ip_info{IP}{$this_ip}{OS});
    my $num_boot_time = 0;
    $num_boot_time = scalar(keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME} }) if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME});

    ## True Positive
    if($num_os >= 2 and $num_boot_time >= 2) {
        $cnt_ip ++;
        $tp ++;
    }
    ## True Negative
    elsif($num_os <= 1 and $num_boot_time <= 1) {
        $cnt_ip ++;
        $tn ++;
    }
    ## False Positive
    elsif($num_os <= 1 and $num_boot_time >= 2) {
        ## see if a group of boot_time miss OS
        my $valid = 1;
        foreach my $this_group_boot_time (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME} }) {
            ## check each flow of this group
            my $os_found = 0;
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN} }) {
                if(exists $ip_info{IP}{$this_ip}{GROUP_BOOT_TIME}{$this_group_boot_time}{CONN}{$this_conn}{OS}) {
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

        if($valid == 1) {
            $cnt_ip ++;
            $fp ++;
        }
        else {
            $cnt_invalid_ip ++;
        }
    }
    ## False Negative
    elsif($num_os >= 2 and $num_boot_time <= 1) {
        ## see if an OS miss boot time
        my $valid = 1;
        foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
            ## check each flow of OS
            my $boot_found = 0;
            if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}) {
                foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN} }) {
                    if(exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME}) {
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

        if($valid == 1) {
            $cnt_ip ++;
            $fn ++;
        }
        else {
            $cnt_invalid_ip ++;
        }
    }
}


############################################################
## Output
############################################################
print STDERR "start to generate output..\n" if($DEBUG2);
open FH_ALL, ">> $output_dir/user_agent_vs_boot_time.txt" or die $!;
print FH_ALL "$cnt_ip, $cnt_invalid_ip, $tp, $tn, $fp, $fn\n";
close FH_ALL;

print "\n valid_ip, invalid_ip, tp, tn, fp, fn\n";
print "$cnt_ip, $cnt_invalid_ip, $tp, $tn, $fp, $fn\n";


