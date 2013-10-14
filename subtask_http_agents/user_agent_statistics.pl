#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/18 @ Narus
##
## User Agent statistics
## a) CDF of # flows have UA per IP
## b) OS types of flows
## c) OS types of IPs
## d) device types of flows
## e) device types of IPs
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
##
##  e.g.
##      perl user_agent_statistics.pl 49
##      perl user_agent_statistics.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
##################################################

use strict;
use List::Util qw(sum max min);
use Tethering;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 0; ## print more


my $FIX_FREQ       = 1; ## fix frequency
my $PLOT_EPS       = 1; ## 1 to output eps; 0 to output png figure
my $PLOT_LOGX      = 0; ## 1 to plot log x; 0 otherwise
my $PLOT_TIMESTAMP = 0; ## 1 to plot received time v.s. Timestamp -- not very useful

my $FIX_DST      = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DST_ADDR = "192.168.5.67";
my $FIX_SRC      = 1; ## 1 to fix the TCP src
# my $FIX_SRC_ADDR  = "10.0.2.4";
# my $FIX_SRC_ADDR  = "128.83";
# my $FIX_SRC_ADDR  = "128.83.144.185";
my $FIX_SRC_ADDR = "^28\.";
# my $FIX_SRC_ADDR  = "^10.";
# my $FIX_SRC_ADDR  = "28.222.137.183";

## The IP to be plotted
# my $PLOT_IP       = "10.0.2.4"; 
# my $PLOT_IP       = "128.83";
# my $PLOT_IP       = "192.168";
my $PLOT_IP       = "28.222.245.159";

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "VM670", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox", "Wii");
my @devices         = ("HTC", "Samsung", "Samsung",  "LG",    "LG",  "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox", "Wii");


#####
## variables
my $input_dir_tcp = "/data/ychen/sprint/text2";
my $input_dir_ua  = "/data/ychen/sprint/text3";
my $output_dir = "./output_statistics";
my $figure_dir = "./figure_statistics";
my $gnuplot_file = "plot_statistics.plot";

my $file_name;
my $file_name_tcp;
my $file_name_ua;

my %ip_info;        ## IP
                    ## IP - CONN - TCP
                    ## IP - CONN - AGENT
                    ## IP - CONN - OS
                    ## IP - TCP
                    ## IP - AGENT
                    ## IP - OS

#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
if($ARGV[0] =~ /^\d+$/) {
    my $file_id = $ARGV[0];
    $file_name = "omni.out.$file_id.eth.pcap.txt";
    $file_name_tcp = "$input_dir_tcp/$file_name";
    $file_name_ua  = "$input_dir_ua/$file_name";
}
else {
    $file_name = $ARGV[0];
    $file_name_tcp = "/data/ychen/testbed/tcp_traces/text2/$file_name";
    $file_name_ua  = "/data/ychen/testbed/tcp_traces/text3/$file_name";
    if(! -e $file_name_tcp) {
        $file_name_tcp = "/data/ychen/testbed/3g_measurement/text2/$file_name";
        $file_name_ua  = "/data/ychen/testbed/3g_measurement/text3/$file_name";
    }
}
print "input file name = $file_name_tcp\n" if($DEBUG2);
print "input file name = $file_name_ua\n" if($DEBUG2);



####################################################
## Read Files
####################################################

## TCP
print STDERR "start to read TCP data..\n" if($DEBUG2);
open FH, $file_name_tcp or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    print "> $_" if($DEBUG1);
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0;
    

    next if($FIX_SRC and !($src =~ /$FIX_SRC_ADDR/));
    next if($FIX_DST and !($dst =~ /$FIX_DST_ADDR/));
    
    ## skip duplicate packets (seq and rx time are the same)
    # if(exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}) {
    #     next if($seq == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}[-1] and 
    #             ($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}[-1]);
    # }
    
    $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TCP} = 1;
    $ip_info{IP}{$src}{TCP} = 1;
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
        next if($FIX_SRC and (!($src =~ /$FIX_SRC_ADDR/ )));
        next if($FIX_DST and (!($dst =~ /$FIX_DST_ADDR/)));


        my ($tag, $val) = split(/: |\r/, $line);
        chomp $tag;
        chomp $val;
        print "    ($tag, $val)\n" if($DEBUG1);

        ## User-Agent
        if($tag =~ /User.*Agent/i) {
            die "it's impossible to have UA but no TCP\n" if(!exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TCP});
            $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{AGENT}{$val} = 1;
            $ip_info{IP}{$src}{AGENT}{$val} = 1;
        }
    }
}
close FH;


############################################################
## identify OS and devices
############################################################
print STDERR "start to identify OS..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});

        my @tmp_ua = (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} });
        my @os = Tethering::_identify_os(\@tmp_ua, \@OS_keywords, \@OSs);
        die "one flow should just have one OS\n" if(scalar(@os) > 1);

        if(scalar(@os) == 1) {
            my $os = $os[0];
            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} = $os;
            $ip_info{IP}{$this_ip}{OS}{$os} = 1;
        }
    }
}

print STDERR "start to identify devices..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});

        my @tmp_ua = (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} });
        my @this_devices = Tethering::_identify_os(\@tmp_ua, \@device_keywords, \@devices);
        die "one flow should just have one device\n" if(scalar(@this_devices) > 1);

        if(scalar(@this_devices) == 1) {
            my $this_device = $this_devices[0];
            $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} = $this_device;
            $ip_info{IP}{$this_ip}{DEVICE}{$this_device} = 1;
        }
    }
}

############################################################
## Statistics
## a) CDF of # flows have UA per IP
## b) OS types of flows
## c) OS types of IPs
## d) device types of flows
## e) device types of IPs
############################################################

############################################################
## a) CDF of # flows have UA per IP
############################################################

## XXX: seems not very interesting. skip it for now

############################################################
## b) OS types of flows
############################################################
print STDERR "b) OS types of flows\n" if($DEBUG2);
my $num_no_ua = 0;
my $num_win = 0;
my $num_apple = 0;
my $num_linux = 0;
my $num_android = 0;
my $num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        die "should always have tcp\n" if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TCP});

        if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
            $num_no_ua ++;
        }
        elsif(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS}) {
            $num_unknown ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} eq "Windows") {
            $num_win ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} eq "Android") {
            $num_android ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} eq "Apple") {
            $num_apple ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} eq "Linux") {
            $num_linux ++;
        }
        else {
            die "should not have other OS: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS}."\n";
        }
    }
}

open FH, ">> $output_dir/ua_flow_os.txt" or die $!;
print FH "$num_no_ua, $num_android, $num_apple, $num_win, $num_linux, $num_unknown\n";
close FH;


############################################################
## c) OS types of IPs
############################################################
print STDERR "c) OS types of IPs\n" if($DEBUG2);
$num_no_ua = 0;
$num_win = 0;
$num_apple = 0;
$num_linux = 0;
$num_android = 0;
$num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    die "IP should always have tcp\n" if(!exists $ip_info{IP}{$this_ip}{TCP});
    
    if(!exists $ip_info{IP}{$this_ip}{AGENT}) {
        $num_no_ua ++;
    }
    elsif(!exists $ip_info{IP}{$this_ip}{OS}) {
        $num_unknown ++;
    }
    else {
        foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
            if($this_os eq "Windows") {
                $num_win ++;
            }
            elsif($this_os eq "Android") {
                $num_android ++;
            }
            elsif($this_os eq "Apple") {
                $num_apple ++;
            }
            elsif($this_os eq "Linux") {
                $num_linux ++;
            }
            else {
                die "should not have other OS: $this_os\n";
            }
        }
    }
}

open FH, ">> $output_dir/ua_ip_os.txt" or die $!;
print FH "$num_no_ua, $num_android, $num_apple, $num_win, $num_linux, $num_unknown\n";
close FH;


############################################################
## d) device types of flows
##  "HTC", "Samsung", "LG", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox", "Wii"
############################################################
print STDERR "d) device types of flows\n" if($DEBUG2);
my $num_no_ua = 0;
my $num_htc = 0;
my $num_samsung = 0;
my $num_lg = 0;
my $num_nokia = 0;
my $num_winphone = 0;
my $num_ipad = 0;
my $num_iphone = 0;
my $num_macbook = 0;
my $num_xbox = 0;
my $num_wii = 0;
my $num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        die "should always have tcp\n" if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TCP});

        if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
            $num_no_ua ++;
        }
        elsif(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE}) {
            $num_unknown ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "Windows Phone") {
            $num_winphone ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "HTC") {
            $num_htc ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "Samsung") {
            $num_samsung ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "LG") {
            $num_lg ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "NOKIA") {
            $num_nokia ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "iPad") {
            $num_ipad ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "iPhone") {
            $num_iphone ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "MacBookAir") {
            $num_macbook ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "Xbox") {
            $num_xbox ++;
        }
        elsif($ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} eq "Wii") {
            $num_wii ++;
        }
        else {
            die "should not have other DEVICE: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE}."\n";
        }
    }
}

open FH, ">> $output_dir/ua_flow_device.txt" or die $!;
print FH "$num_no_ua, $num_samsung, $num_htc, $num_ipad, $num_iphone, $num_macbook, $num_lg, $num_nokia, $num_winphone, $num_xbox, $num_wii, $num_unknown\n";
close FH;


############################################################
## e) device types of IPs
############################################################
print STDERR "e) device types of IPs\n" if($DEBUG2);
$num_no_ua = 0;
$num_htc = 0;
$num_samsung = 0;
$num_lg = 0;
$num_nokia = 0;
$num_winphone = 0;
$num_ipad = 0;
$num_iphone = 0;
$num_macbook = 0;
$num_xbox = 0;
$num_wii = 0;
$num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    die "IP should always have tcp\n" if(!exists $ip_info{IP}{$this_ip}{TCP});
    
    if(!exists $ip_info{IP}{$this_ip}{AGENT}) {
        $num_no_ua ++;
    }
    elsif(!exists $ip_info{IP}{$this_ip}{DEVICE}) {
        $num_unknown ++;
    }
    else {
        foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) {
            if($this_device eq "Windows Phone") {
                $num_winphone ++;
            }
            elsif($this_device eq "HTC") {
                $num_htc ++;
            }
            elsif($this_device eq "Samsung") {
                $num_samsung ++;
            }
            elsif($this_device eq "LG") {
                $num_lg ++;
            }
            elsif($this_device eq "NOKIA") {
                $num_nokia ++;
            }
            elsif($this_device eq "iPad") {
                $num_ipad ++;
            }
            elsif($this_device eq "iPhone") {
                $num_iphone ++;
            }
            elsif($this_device eq "MacBookAir") {
                $num_macbook ++;
            }
            elsif($this_device eq "Xbox") {
                $num_xbox ++;
            }
            elsif($this_device eq "Wii") {
                $num_wii ++;
            }
        }
    }
}

open FH, ">> $output_dir/ua_ip_device.txt" or die $!;
print FH "$num_no_ua, $num_samsung, $num_htc, $num_ipad, $num_iphone, $num_macbook, $num_lg, $num_nokia, $num_winphone, $num_xbox, $num_wii, $num_unknown\n";
close FH;
