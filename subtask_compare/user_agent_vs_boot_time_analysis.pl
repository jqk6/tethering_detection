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
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print more
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

my $FLOW_WITH_OS_ONLY = 1;  ## 1 to take into account flows with OS info

my $BOOT_TIME_FREQ = 0;  ## 0: to use estimated freq, 1 to use 100Hz
my $BOOT_TIME_INTERVAL_THRESHOLD = 3;  ## the boot time interval between two devices should be larger than this threshold
my $BOOT_TIME_SPAN_THRESHOLD = 3;  ## the boot time interval between packets should be smaller than this threshold
my $FLOW_PKT_NUM_THRESHOLD = 30;
my $FLOW_DURATION_THRESHOLD = 5;

my @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux", "Xbox");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");
my @devices         = ("HTC", "Samsung", "Samsung",  "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");


#####
## variables
my $input_dir_timestamp  = "/data/ychen/sprint/text5";
my $input_dir_user_agent = "/data/ychen/sprint/text3";
my $output_dir = "./output_analysis";
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
if($iteration == 0) {
    $BOOT_TIME_FREQ = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 3600;
    $BOOT_TIME_SPAN_THRESHOLD = 3;
    $FLOW_PKT_NUM_THRESHOLD = 10;
    $FLOW_DURATION_THRESHOLD = 1;
    @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}
elsif($iteration == 1) {
    $BOOT_TIME_FREQ = 0;
    $BOOT_TIME_INTERVAL_THRESHOLD = 3;
    $BOOT_TIME_SPAN_THRESHOLD = 5;
    $FLOW_PKT_NUM_THRESHOLD = 10;
    $FLOW_DURATION_THRESHOLD = 5;
    @CLOCK_FREQ = (2, 10, 100, 128, 200, 1000);
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
my %tethering_ip = ();
my %untethering_ip = ();
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
                    $ip_info{IP}{$this_ip}{OS}{$os} = () if(!exists $ip_info{IP}{$this_ip}{OS}{$os});
                }
                print "  - OS: $os\n" if($DEBUG3);
            }

            if($FLOW_WITH_OS_ONLY) {
                next if($os eq "");
            }

            ## Boot time of the flow
            my ($freq, $boot_time);
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME}) {
                # ($freq, $boot_time) = Tethering::est_freq_boottime_enumeration1(
                #                             \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }, 
                #                             \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} });
                ($freq, $boot_time) = Tethering::_est_freq_boottime_enumeration(
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} }, 
                                            \@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TX_TIME} },
                                            \@CLOCK_FREQ,
                                            $BOOT_TIME_FREQ,
                                            $BOOT_TIME_SPAN_THRESHOLD,
                                            $FLOW_PKT_NUM_THRESHOLD,
                                            $FLOW_DURATION_THRESHOLD);
                
                print "  - boot time: $boot_time\n" if($DEBUG3 and $freq > 0);
                print "  - freq: $freq\n" if($DEBUG3 and $freq > 0);

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
        } ## end for each flow


        # print STDERR "start to get tethering / untethering IPs\n";
        # my %tmp = ();
        my $num_os = 0;
        foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
            next if(!exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN});
            my $found = 0;
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN} }) {
                next if(!exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME});
                $found = 1;
                # $tmp{GROUP}{$this_os}{CONN}{$this_conn}{BOOT_TIME} = $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME};
            }
            $num_os += $found;
        }
        print "==> os ($num_os):\n";

        # my $num_os = scalar(keys %{ $tmp{GROUP} });
        if($num_os > 1) {
            # print "O: $this_ip: ".join(",", (keys %{ $tmp{GROUP} }))."\n";
            # if(exists $tethering_ip{IP}{$this_ip}) {
            #     my %tmp2 = (%{ $tethering_ip{IP}{$this_ip} }, %tmp);
            #     %{ $tethering_ip{IP}{$this_ip} } = %tmp2;    
            # }
            # else {
            #     %{ $tethering_ip{IP}{$this_ip} } = %tmp;
            # }
            foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                next if(!exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN});
                foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN} }) {
                    next if(!exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME});
                    $tethering_ip{IP}{$this_ip}{GROUP}{$this_os}{CONN}{$this_conn}{BOOT_TIME} = $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME};
                }
            }
            print "O: $this_ip: ".join(",", (keys %{ $tethering_ip{IP}{$this_ip}{GROUP} }))."\n";
            
        }
        elsif($num_os == 1) {
            # if(exists $untethering_ip{IP}{$this_ip}) {
            #     my %tmp2 = (%{ $untethering_ip{IP}{$this_ip} }, %tmp);
            #     %{ $untethering_ip{IP}{$this_ip} } = %tmp2;
            # }
            # else {
            #     %{ $untethering_ip{IP}{$this_ip} } = %tmp;
            # }
            foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                next if(!exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN});
                foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN} }) {
                    next if(!exists $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME});
                    $untethering_ip{IP}{$this_ip}{GROUP}{$this_os}{CONN}{$this_conn}{BOOT_TIME} = $ip_info{IP}{$this_ip}{OS}{$this_os}{CONN}{$this_conn}{BOOT_TIME};
                }
            }
            print "X: $this_ip: ".join(",", (keys %{ $untethering_ip{IP}{$this_ip}{GROUP} }))."\n";
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
print "\n========================\n";
print "tethering\n";
my @tethering_boot_diff = ();
foreach my $this_ip (keys %{ $tethering_ip{IP} }) {
    print "- $this_ip\n";
    my @groups = (keys %{ $tethering_ip{IP}{$this_ip}{GROUP} });
    foreach my $this_gr_i (0 .. scalar(@groups)-2)  {
        my $avg_boot_time1 = 0;
        my $cnt1 = 0;
        foreach my $this_conn1 (keys %{ $tethering_ip{IP}{$this_ip}{GROUP}{$groups[$this_gr_i]}{CONN} }) {
            my $this_boot1 = $tethering_ip{IP}{$this_ip}{GROUP}{$groups[$this_gr_i]}{CONN}{$this_conn1}{BOOT_TIME};
            print "  - ".$groups[$this_gr_i]." ($this_conn1) = $this_boot1\n";
            $avg_boot_time1 += $this_boot1;
            $cnt1 ++;
        }
        $avg_boot_time1 = $avg_boot_time1 / $cnt1;

        foreach my $this_gr_j ($this_gr_i+1 .. scalar(@groups)-1)  {
            my $avg_boot_time2 = 0;
            my $cnt2 = 0;
            foreach my $this_conn2 (keys %{ $tethering_ip{IP}{$this_ip}{GROUP}{$groups[$this_gr_j]}{CONN} }) {
                my $this_boot2 = $tethering_ip{IP}{$this_ip}{GROUP}{$groups[$this_gr_j]}{CONN}{$this_conn2}{BOOT_TIME};
                $avg_boot_time2 += $this_boot2;
                $cnt2 ++;
            }
            $avg_boot_time2 = $avg_boot_time2 / $cnt2;
            push(@tethering_boot_diff, abs($avg_boot_time1 - $avg_boot_time2));
        }
    }
}
print "\n========================\n";
print "untethering\n";
my @untethering_boot_diff = ();
foreach my $this_ip (keys %{ $untethering_ip{IP} }) {
    die "size should == 1\n" if (scalar((keys %{ $untethering_ip{IP}{$this_ip}{GROUP} })) != 1);
    print "- $this_ip (".scalar(keys %{ $untethering_ip{IP}{$this_ip}{GROUP} })."): ";

    foreach my $this_gr (keys %{ $untethering_ip{IP}{$this_ip}{GROUP} }) {
        print "$this_gr (".scalar(keys %{ $untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN} }).")\n";

        my @flows = (keys %{ $untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN} });
        foreach my $flow_i (0 .. scalar(@flows)-2) {
            print "  - $this_gr (".$flows[$flow_i]."): ".$untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN}{$flows[$flow_i]}{BOOT_TIME}."\n";
            foreach my $flow_j ($flow_i+1 .. scalar(@flows)-1) {
                print "  -   $this_gr (".$flows[$flow_j]."): ".$untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN}{$flows[$flow_j]}{BOOT_TIME}." > ".abs($untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN}{$flows[$flow_i]}{BOOT_TIME} - $untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN}{$flows[$flow_j]}{BOOT_TIME})."\n";

                push(@untethering_boot_diff, abs($untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN}{$flows[$flow_i]}{BOOT_TIME} - $untethering_ip{IP}{$this_ip}{GROUP}{$this_gr}{CONN}{$flows[$flow_j]}{BOOT_TIME}));
            }
        }
    }
}


open FH, ">>$output_dir/user_agent_vs_boot_time_analysis_tethering.$iteration.txt" or die $!;
print FH join("\n", @tethering_boot_diff)."\n";
close FH;

open FH, ">>$output_dir/user_agent_vs_boot_time_analysis_untethering.$iteration.txt" or die $!;
print FH join("\n", @untethering_boot_diff)."\n";
close FH;


print "done\n";
1;