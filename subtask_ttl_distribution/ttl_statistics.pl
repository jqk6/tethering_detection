#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/16 @ Narus
##
## get statistcs data of TTL
## a) TCP: ttl distribution
## b) TCP: # of ttl per flow
## c) TCP: # of ttl per IP
## a) UDP: ttl distribution
## b) UDP: # of ttl per flow
## c) UDP: # of ttl per IP
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
##
## - output
##
##  e.g.
##      perl ttl_statistics.pl 49
##      perl ttl_statistics.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
##################################################

use strict;
use List::Util qw(sum max min);

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

my $FIX_DST      = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DST_ADDR = "192.168.5.67";
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


#####
## variables
my $input_dir_tcp  = "/data/ychen/sprint/text2";
my $input_dir_udp  = "/data/ychen/sprint/text4";
my $input_dir_ua  = "/data/ychen/sprint/text3";
my $output_dir = "./output_statistics";
my $figure_dir = "./figure_statistics";
my $gnuplot_file = "plot_ttl.plot";

my $file_name;
my $file_name_tcp;
my $file_name_udp;
my $file_name_ua;
my $iteration;

my %ip_info;        ## TCP:
                    ## IP
                    ## IP - CONN - RX_TIME
                    ## IP - CONN - TTL
                    ## TTL
                    ## TTL - CNT
my %ip_info2;       ## UDP:
                    ## IP
                    ## IP - CONN - RX_TIME
                    ## IP - CONN - TTL
                    ## TTL
                    ## TTL - CNT


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
if($ARGV[0] =~ /^\d+$/) {
    my $file_id = $ARGV[0];
    $file_name     = "omni.out.$file_id.eth.pcap.txt";
    $file_name_tcp = "$input_dir_tcp/$file_name";
    $file_name_udp = "$input_dir_udp/$file_name";
    $file_name_ua  = "$input_dir_ua/$file_name";
}
else {
    $file_name     = $ARGV[0];
    $file_name_tcp = "/data/ychen/testbed/tcp_traces/text2/$file_name";
    $file_name_udp = "/data/ychen/testbed/udp_traces/text4/$file_name";
    $file_name_ua  = "/data/ychen/testbed/tcp_traces/text3/$file_name";
    if(! -e $file_name_tcp) {
        $file_name_tcp = "/data/ychen/testbed/3g_measurement/text2/$file_name";
        $file_name_udp = "/data/ychen/testbed/3g_measurement/text4/$file_name";
        $file_name_ua  = "/data/ychen/testbed/3g_measurement/text3/$file_name";
    }
}
print "input file name = $file_name_tcp\n" if($DEBUG2);
print "input file name = $file_name_udp\n" if($DEBUG2);
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
    if(exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}) {
        next if($seq == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}[-1] and 
                ($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}[-1]);
    }
    
    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}         }, $seq);
    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}     }, $time + $time_usec / 1000000);
    $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TTL}{$ttl} = 1;
}
close FH;


## UDP
print STDERR "start to read UDP data..\n" if($DEBUG2);
open FH, $file_name_udp or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    print "> $_" if($DEBUG1);
    
    ## format
    ##   <time> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <length>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $len) = split(/\s+>*\s*/, $_);
    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $len += 0;
    
    next if($FIX_SRC and !($src =~ /$FIX_SRC_ADDR/));
    next if($FIX_DST and !($dst =~ /$FIX_DST_ADDR/));
    
    push(@{ $ip_info2{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME} }, $time + $time_usec / 1000000);
    $ip_info2{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TTL}{$ttl} = 1;
}
close FH;



############################################################
## a) TTL distribution
##    ip_info: TTL - CNT
############################################################
print STDERR "a) TCP - TTL distribution\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});

    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        ## no ttl
        if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
            $ip_info{TTL}{-1}{CNT} ++;
        }
        ## has 1 or more TTLs
        else {
            foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
                $ip_info{TTL}{$this_ttl} ++;
            }
        }
    }
}

open FH, ">> $output_dir/tcp_ttl_dist.txt" or die $!;
# print FH "#TTL=".join(", ", (-1 .. 255))."\n";
foreach my $ttl (-1 .. 255) {
    if(exists $ip_info{TTL}{$ttl}) {
        print FH $ip_info{TTL}{$ttl}.", ";
    }
    else {
        print FH "0, ";
    }
}
print FH "\n";
close FH;

################################

print STDERR "a) UDP - TTL distribution\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info2{IP} }) {
    next if(!exists $ip_info2{IP}{$this_ip}{CONN});

    foreach my $this_conn (keys %{ $ip_info2{IP}{$this_ip}{CONN} }) {
        ## no ttl
        if(!exists $ip_info2{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
            $ip_info2{TTL}{-1}{CNT} ++;
        }
        ## has 1 or more TTLs
        else {
            foreach my $this_ttl (keys %{ $ip_info2{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
                $ip_info2{TTL}{$this_ttl} ++;
            }
        }
    }
}

open FH, ">> $output_dir/udp_ttl_dist.txt" or die $!;
# print FH "#TTL=".join(", ", (-1 .. 255))."\n";
foreach my $ttl (-1 .. 255) {
    if(exists $ip_info2{TTL}{$ttl}) {
        print FH $ip_info2{TTL}{$ttl}.", ";
    }
    else {
        print FH "0, ";
    }
}
print FH "\n";
close FH;



############################################################
## b) # TTL per flow
##    ip_info: NUM_TTL_PER_FLOW - CNT
############################################################
print STDERR "b) TCP - # TTL per flow\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});

    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        my $num_ttl_per_flow = 0;
        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
            $num_ttl_per_flow = scalar(keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} });
        }
        $ip_info{NUM_TTL_PER_FLOW}{$num_ttl_per_flow} ++;
    }
}

open FH, ">> $output_dir/tcp_ttl_per_flow.txt" or die $!;
# print FH "# num TTL=".join(", ", (0 .. 255))."\n";
foreach my $num_ttl (0 .. 255) {
    if(exists $ip_info{NUM_TTL_PER_FLOW}{$num_ttl}) {
        print FH $ip_info{NUM_TTL_PER_FLOW}{$num_ttl}.", ";
    }
    else {
        print FH "0, ";
    }
}
print FH "\n";
close FH;

###################################

print STDERR "b) UDP - # TTL per flow\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info2{IP} }) {
    next if(!exists $ip_info2{IP}{$this_ip}{CONN});

    foreach my $this_conn (keys %{ $ip_info2{IP}{$this_ip}{CONN} }) {
        my $num_ttl_per_flow = 0;
        if(exists $ip_info2{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
            $num_ttl_per_flow = scalar(keys %{ $ip_info2{IP}{$this_ip}{CONN}{$this_conn}{TTL} });
        }
        $ip_info2{NUM_TTL_PER_FLOW}{$num_ttl_per_flow} ++;
    }
}

open FH, ">> $output_dir/udp_ttl_per_flow.txt" or die $!;
# print FH "# num TTL=".join(", ", (0 .. 255))."\n";
foreach my $num_ttl (0 .. 255) {
    if(exists $ip_info2{NUM_TTL_PER_FLOW}{$num_ttl}) {
        print FH $ip_info2{NUM_TTL_PER_FLOW}{$num_ttl}.", ";
    }
    else {
        print FH "0, ";
    }
}
print FH "\n";
close FH;


############################################################
## c) # TTL per IP
##    ip_info: NUM_TTL_PER_IP - CNT
############################################################
print STDERR "c) TCP - # TTL per IP\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    next if(!exists $ip_info{IP}{$this_ip}{CONN});

    my %tmp = ();
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL});
        
        foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
            $tmp{$this_ttl} = 1;
        }
    }
    my $num_ttl_per_ip = scalar(keys %tmp);
    $ip_info{NUM_TTL_PER_IP}{$num_ttl_per_ip} ++;
}

open FH, ">> $output_dir/tcp_ttl_per_ip.txt" or die $!;
# print FH "# num TTL=".join(", ", (0 .. 255))."\n";
foreach my $num_ttl (0 .. 255) {
    if(exists $ip_info{NUM_TTL_PER_IP}{$num_ttl}) {
        print FH $ip_info{NUM_TTL_PER_IP}{$num_ttl}.", ";
    }
    else {
        print FH "0, ";
    }
}
print FH "\n";
close FH;

###############################

print STDERR "c) UDP - # TTL per IP\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info2{IP} }) {
    next if(!exists $ip_info2{IP}{$this_ip}{CONN});

    my %tmp = ();
    foreach my $this_conn (keys %{ $ip_info2{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info2{IP}{$this_ip}{CONN}{$this_conn}{TTL});
        
        foreach my $this_ttl (keys %{ $ip_info2{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
            $tmp{$this_ttl} = 1;
        }
    }
    my $num_ttl_per_ip = scalar(keys %tmp);
    $ip_info2{NUM_TTL_PER_IP}{$num_ttl_per_ip} ++;
}

open FH, ">> $output_dir/udp_ttl_per_ip.txt" or die $!;
# print FH "# num TTL=".join(", ", (0 .. 255))."\n";
foreach my $num_ttl (0 .. 255) {
    if(exists $ip_info2{NUM_TTL_PER_IP}{$num_ttl}) {
        print FH $ip_info2{NUM_TTL_PER_IP}{$num_ttl}.", ";
    }
    else {
        print FH "0, ";
    }
}
print FH "\n";
close FH;


