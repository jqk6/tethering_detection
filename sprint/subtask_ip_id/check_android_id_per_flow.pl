#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/20 @ Narus
##
## Check if the IP ID increase linearly in Android flows
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
##     e) FIX_DEST  : only target the pkts to some destination node
##
##  e.g.
##      perl check_android_id_per_flow.pl 49
##      perl check_android_id_per_flow.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
##################################################

use strict;
use List::Util qw(sum max min);
# use MyUtil;
use Tethering;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print more
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
# my $FIX_SRC_ADDR  = "^28\.";
# my $FIX_SRC_ADDR  = "^10.";
# my $FIX_SRC_ADDR  = "28.222.137.183";
my $FIX_SRC_ADDR  = "^192.168\.";

## The IP to be plotted
# my $PLOT_IP       = "10.0.2.4"; 
# my $PLOT_IP       = "128.83";
# my $PLOT_IP       = "192.168";
my $PLOT_IP       = "28.222.245.159";


my $BOOT_TIME_INTERVAL_THRESHOLD = 3;  ## the boot time interval between two devices should be larger than this threshold
my $BOOT_TIME_SPAN_THRESHOLD = 3;  ## the boot time interval between packets should be smaller than this threshold

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux", "Xbox");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");
my @devices         = ("HTC", "Samsung", "Samsung",  "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");

my @MAJOR_TTLS = (63, 127);

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
                    ## IP - CONN - AGENT
                    ## IP - CONN - OS
                    ## IP - CONN - IP ID



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
    if(! -e $file_name_ts) {
        $file_name_ts = "/data/ychen/testbed/exp2/text5/$file_name";
        $file_name_ua = "/data/ychen/testbed/exp2/text3/$file_name";
    }
}
print STDERR "input file name = $file_name_ts\n" if($DEBUG2);
print STDERR "input file name = $file_name_ua\n" if($DEBUG2);




####################################################
## Read Files
####################################################

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
    print "$line" if($DEBUG1);
    while($line = <FH>) {
        print "$line" if($DEBUG1);
        last if($line eq "\n");
        next if($FIX_SRC  and (!($src =~ /$FIX_SRC_ADDR/ )));
        next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));

        my ($tag, $val) = split(/: |\r/, $line);
        chomp $tag;
        chomp $val;
        print "    ($tag, $val)\n" if($DEBUG1);

        ## User-Agent
        if($tag =~ /User.*Agent/i) {
            next if($seq == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}[-1] and 
                    ($time + $time_usec/1000000) == $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME}[-1] );
            push(@{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ} }, $seq);
            push(@{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME} }, $time + $time_usec/1000000);
            $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{AGENT}{$val} = 1;
            push(@{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{ID} }, $id);
        }
    }
}
close FH;



############################################################
## Calculate boot time and identify OS
############################################################
print STDERR "start to Calculate boot time and identify OS..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    #################################
    ## Flow:
    ##   IP - Flow |- ID
    ##             |- User_Agent
    ##             |- OS
    ##
    if(exists($ip_info{IP}{$this_ip}{CONN})) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            

            ## OS of the flow
            my $os = "";
            if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
                my @tmp_user_agents = (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} });
                my @os = Tethering::_identify_os(\@tmp_user_agents, \@OS_keywords, \@OSs);
                print STDERR "one flow should just have one OS\n" if($DEBUG0 and scalar(@os) > 1);

                if(scalar(@os) == 1) {
                    $os = $os[0];
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} = $os;
                }
            }
            else {
                die "there must be User Agent\n";
            }

            if( ($os eq "Android" or $os eq "Windows" or $os eq "Linux") and 
                scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID} }) > 0) {
                print "$this_ip -- $this_conn -- $os: \n" if($DEBUG3);
                print join(",", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID} })."\n" if($DEBUG3);
                print join(",", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} })."\n" if($os eq "Windows" and $DEBUG3);
                foreach my $ind (1 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID} })-1) {
                    if($ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind] - $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind-1] < 0) {
                        ## become smaller or equal
                        if($ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind-1] > 60000 or 
                           $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind] < 100) {
                            print STDERR "> might be wrap around ($os)\n";
                            print "> might be wrap around ($os)\n";
                        }
                        else {
                            print STDERR "> not increasing!! ($os)\n";
                            print "> not increasing!! ($os)\n";
                        }
                        
                    }
                }
            }   ## if Android         
        }
    }
}
