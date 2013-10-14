#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/16 @ Narus
##
## TCP Timestamp statistics
## a) # flows w/ and w/o TS
## b) # IPs w/ and w/o TS
## c) # flows w/ TS of various OS
## d) # IPs w/ TS of various OS
## e) # flows w/o TS of various OS
## f) # IPs w/o TS of various OS
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
##
##  e.g.
##      perl timestamp_statistics.pl 49
##      perl timestamp_statistics.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
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
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "VM670", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");
my @devices         = ("HTC", "Samsung", "Samsung",  "LG",    "LG",  "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");


#####
## variables
my $input_dir_tcp = "/data/ychen/sprint/text2";
my $input_dir_ts  = "/data/ychen/sprint/text5";
my $input_dir_ua  = "/data/ychen/sprint/text3";
my $output_dir = "./output_statistics";
my $figure_dir = "./figure_statistics";
my $gnuplot_file = "plot_statistics.plot";

my $file_name;
my $file_name_tcp;
my $file_name_ts;
my $file_name_ua;
my $iteration;

my %ip_info;        ## IP
                    ## IP - CONN - TCP
                    ## IP - CONN - TIMESTAMP
                    ## IP - CONN - AGENT
                    ## IP - CONN - OS
                    ## IP - TCP
                    ## IP - TIMESTAMP
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
    $file_name_ts  = "$input_dir_ts/$file_name";
    $file_name_ua  = "$input_dir_ua/$file_name";
}
else {
    $file_name = $ARGV[0];
    $file_name_tcp = "/data/ychen/testbed/tcp_traces/text2/$file_name";
    $file_name_ts  = "/data/ychen/testbed/tcp_traces/text5/$file_name";
    $file_name_ua  = "/data/ychen/testbed/tcp_traces/text3/$file_name";
    if(! -e $file_name_ts) {
        $file_name_tcp = "/data/ychen/testbed/3g_measurement/text2/$file_name";
        $file_name_ts  = "/data/ychen/testbed/3g_measurement/text5/$file_name";
        $file_name_ua  = "/data/ychen/testbed/3g_measurement/text3/$file_name";
    }
}
print "input file name = $file_name_tcp\n" if($DEBUG2);
print "input file name = $file_name_ts\n" if($DEBUG2);
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


    next if($FIX_SRC and (!($src =~ /$FIX_SRC_ADDR/)));
    next if($FIX_DST and (!($dst =~ /$FIX_DST_ADDR/)));
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $tcp_ts_val, $tcp_ts_ecr))."\n" if($DEBUG1);


    ## check if it's a reordering / retransmission
    # next if(exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ} and $seq < $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}[-1]);
    ## check if it's a duplicate
    # next if(exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TX_TIME} and 
    #         $tcp_ts_val == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TX_TIME}[-1] and 
    #         ($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}[-1] and 
    #         $seq == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}[-1]);

    if(!exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TCP}) {
        print "src=$src, s_port=$s_port, dst=$dst, d_port=$d_port\n";
        print  "it's impossible to have TS but no TCP\n";
        die "\n";
    }
    $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TIMESTAMP} = 1;
    $ip_info{IP}{$src}{TIMESTAMP} = 1;
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
## identify OS
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

############################################################
## Statistics
## a) # flows w/ and w/o TS
## b) # IPs w/ and w/o TS
## c) # flows w/ TS of various OS
## d) # IPs w/ TS of various OS
## e) # flows w/o TS of various OS
## f) # IPs w/o TS of various OS
############################################################

############################################################
## a) # flows w/ and w/o TS
############################################################
print STDERR "a) # flows w/ and w/o TS\n" if($DEBUG2);
my $num_tcp_flow = 0;
my $num_ts_flow = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TCP});

        $num_tcp_flow ++;
        $num_ts_flow ++ if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TIMESTAMP});
    }
}

open FH, ">> $output_dir/ts_w_wo_ts_flow.txt" or die $!;
print FH "$num_tcp_flow, $num_ts_flow, ".($num_tcp_flow - $num_ts_flow)."\n";
close FH;


############################################################
## b) # IPs w/ and w/o TS
############################################################
print STDERR "b) # IPs w/ and w/o TS\n" if($DEBUG2);
my $num_tcp_ip = 0;
my $num_ts_ip = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{TCP});
    
    $num_tcp_ip ++;
    $num_ts_ip ++ if(exists $ip_info{IP}{$this_ip}{TIMESTAMP});
}

open FH, ">> $output_dir/ts_w_wo_ts_ip.txt" or die $!;
print FH "$num_tcp_ip, $num_ts_ip, ".($num_tcp_ip - $num_ts_ip)."\n";
close FH;



############################################################
## c) # flows w/ TS of various OS
############################################################
print STDERR "c) # flows w/ TS of various OS\n" if($DEBUG2);
my $num_no_ua = 0;
my $num_win = 0;
my $num_apple = 0;
my $num_linux = 0;
my $num_android = 0;
my $num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TIMESTAMP});

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

open FH, ">> $output_dir/ts_flow_w_ts_os.txt" or die $!;
print FH "$num_no_ua, $num_android, $num_apple, $num_win, $num_linux, $num_unknown\n";
close FH;


############################################################
## d) # IPs w/ TS of various OS
############################################################
print STDERR "c) # IPs w/ TS of various OS\n" if($DEBUG2);
$num_no_ua = 0;
$num_win = 0;
$num_apple = 0;
$num_linux = 0;
$num_android = 0;
$num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{TIMESTAMP});
    
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

open FH, ">> $output_dir/ts_ip_w_ts_os.txt" or die $!;
print FH "$num_no_ua, $num_android, $num_apple, $num_win, $num_linux, $num_unknown\n";
close FH;


############################################################
## e) # flows w/o TS of various OS
############################################################
print STDERR "e) # flows w/o TS of various OS\n" if($DEBUG2);
$num_no_ua = 0;
$num_win = 0;
$num_apple = 0;
$num_linux = 0;
$num_android = 0;
$num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TIMESTAMP});

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

open FH, ">> $output_dir/ts_flow_wo_ts_os.txt" or die $!;
print FH "$num_no_ua, $num_android, $num_apple, $num_win, $num_linux, $num_unknown\n";
close FH;


############################################################
## f) # IPs w/o TS of various OS
############################################################
print STDERR "f) # IPs w/o TS of various OS\n" if($DEBUG2);
$num_no_ua = 0;
$num_win = 0;
$num_apple = 0;
$num_linux = 0;
$num_android = 0;
$num_unknown = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(exists $ip_info{IP}{$this_ip}{TIMESTAMP});

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

open FH, ">> $output_dir/ts_ip_wo_ts_os.txt" or die $!;
print FH "$num_no_ua, $num_android, $num_apple, $num_win, $num_linux, $num_unknown\n";
close FH;
