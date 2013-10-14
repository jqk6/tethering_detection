#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/08/14 @ Narus 
##
## analyze TCP cwnd to identify TCP flavor
##
## - input: parsed_pcap_text
##     a) tcp packets: text2
##      format
##      <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
##
## - output
##     ./output/
##
##  e.g.
##      perl analyze_tcp_cwnd.pl 49
##################################################

use strict;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug
my $DEBUG3 = 1; ## print out detailed statistics
my $DEBUG4 = 0; ## print out detailed statistics for each packet

my $PLOT_EPS     = 1; ## 1 to output eps; 0 to output png figure
my $FIX_DST      = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DST_ADDR = "192.168.5.67";
my $FIX_SRC      = 1; ## 1 to fix the TCP src
# my $FIX_SRC_ADDR = "10.0.2.4";
# my $FIX_SRC_ADDR = "128.83";
# my $FIX_SRC_ADDR = "128.83.144.185";
my $FIX_SRC_ADDR = "^28\.";
# my $FIX_SRC_ADDR = "28.253.147.95";
# my $FIX_SRC_ADDR = "^10.";
# my $FIX_SRC_ADDR = "^192\.";
# my $FIX_SRC_ADDR = "28.222.137.183";

my $MIN_NUM_PKTS  = 20;
my $MSS           = 1000;
my $INIT_CWND     = 2 * $MSS;

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux", "Xbox");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");
my @devices         = ("HTC", "Samsung", "Samsung",  "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");


#####
## variables
my $output_dir = "./output";
my $figure_dir = "./figures";
my $input_dir_tcp = "/data/ychen/sprint/text2";
my $input_dir_tcp_win = "/data/ychen/sprint/text6";
my $input_dir_ua = "/data/ychen/sprint/text3";

my $gnuplot_file = "plot_win.plot";

my $file_name;
my $file_name_tcp;
my $file_name_win;
my $file_name_ua;

my %ip_info;        ## IP
                    ## IP - Flow - Receiving window size
                    ## IP - Flow - Time
                    ## IP - Flow - Scale


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
    $file_name_win = "$input_dir_tcp_win/$file_name";
    $file_name_ua = "$input_dir_ua/$file_name";
}
else {
    $file_name = $ARGV[0];
    $file_name_tcp = "/data/ychen/testbed/tcp_traces/text2/$file_name";
    $file_name_win = "/data/ychen/testbed/tcp_traces/text6/$file_name";
    $file_name_ua = "/data/ychen/testbed/tcp_traces/text3/$file_name";
    if(! -e $file_name_tcp) {
        $file_name_tcp = "/data/ychen/testbed/3g_measurement/text2/$file_name";
        $file_name_win = "/data/ychen/testbed/3g_measurement/text6/$file_name";
        $file_name_ua = "/data/ychen/testbed/3g_measurement/text3/$file_name";
    }
}


#####
## main starts here
print STDERR "start to read TCP data..\n" if($DEBUG2);
open FH, "$file_name_tcp" or die "$file_name_tcp\n".$!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0;
    

    # next if($FIX_SRC and !($src =~ /$FIX_SRC_ADDR/));
    # next if($FIX_DST and !($dst =~ /$FIX_DST_ADDR/));
    if(exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}) {
        next if($seq == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}[-1] and 
            ($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}[-1]);
    }
    if(exists $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{ACK}) {
        next if($ack == $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{ACK}[-1] and 
            ($time + $time_usec / 1000000) == $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{RX_TIME}[-1]);
    }
    

    ## check if it's a reordering / retransmission
    # next if(exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ} and $seq < $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}[-1]);

    if($src =~ /$FIX_SRC_ADDR/ and ($payload_len > 0 or $is_syn == 1) ) {
        print ">".join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len))."\n" if($DEBUG1);

        push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}         }, $seq);
        push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{ACK}         }, -1);
        push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{PAYLOAD_LEN} }, $payload_len);
        push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{WIN}         }, -1);
        push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}     }, $time + $time_usec / 1000000);
        push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{IS_SYN}      }, $is_syn);
    }
    elsif($dst =~ /$FIX_SRC_ADDR/ and $is_ack == 1) {
        print "<".join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len))."\n" if($DEBUG1);

        push(@{ $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{SEQ}         }, -1);
        push(@{ $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{ACK}         }, $ack);
        push(@{ $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{PAYLOAD_LEN} }, -1);
        push(@{ $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{WIN}         }, $win);
        push(@{ $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{RX_TIME}     }, $time + $time_usec / 1000000);
        push(@{ $ip_info{IP}{$dst}{CONN}{"$d_port:$src:$s_port"}{IS_SYN}      }, -1);
    }

    die if($payload_len < 0);
}
close FH;


#####
## Analyze
my $num_flows = 0;               ## number of valid flows: a) have syn, b) > X pkts, c) error dup
my $num_flow_invalid_syn = 0;    ## number of invalide flows (which do not have syn)
my $num_flow_invalid_pkt = 0;    ## number of invalide flows (which do not have syn)

my @num_pkts = ();          ## number of packets per flow
print STDERR "start to analyze result..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SEQ});

        my $pre_rx_time = -1;
        my $pre_seq = -1;
        my $pre_len = -1;
        my $pre_ack = -1;
        my $num_dup_ack = 0;
        
        my $rx_win  = -1;
        my $num_tx_pkts = 0;
        my $num_rx_ack  = 0;
        my $inflight_pkt_bytes = 0;
        my $inflight_pkt_num = 0;
        my @inflight_pkt_bytes = ();
        my @inflight_pkt_num = ();
        my $cwnd_tahoe = $INIT_CWND;
        my $cwnd_reno = $INIT_CWND;
        my $sshresh_tahoe = 65536;
        my $sshresh_reno = 65536;
        my @cwnd_tahoe = ();
        my @cwnd_reno = ();
        my @rx_win    = ();

        ## Check if the flow is valid
        ## a) have syn
        # if($ip_info{IP}{$this_ip}{CONN}{$this_conn}{IS_SYN}[0] != 1) {
        #     $num_flow_invalid_syn ++;
        #     next;
        # }
        
        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SEQ} })-1) {
            my $seq          = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SEQ}[$ind];
            my $ack          = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ACK}[$ind];
            my $payload_len  = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{PAYLOAD_LEN}[$ind];
            my $win          = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN}[$ind];
            my $rx_time      = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind];
            my $is_syn       = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{IS_SYN}[$ind];

            if($seq >= 0) {
                if($DEBUG3) {
                    print "$this_ip - $this_conn: ";
                    if($is_syn == 1) {
                        print "SYNC, ";
                    }
                    else {
                        print "DATA, ";
                    }
                    print "seq=$seq, payload=$payload_len\n";
                }

                
                $num_tx_pkts ++;

                if($is_syn == 1) {
                    ## the 1st packet: SYNC 
                    $pre_ack = $seq + 1;
                    $pre_seq = $seq;
                    $pre_len = 0;
                    $pre_rx_time = $rx_time;
                }
                elsif($seq > $pre_seq) {
                    ## new data sent
                    $pre_seq = $seq;
                    $pre_len = $payload_len;
                    $pre_rx_time = $rx_time;

                }
                elsif($seq == $pre_seq and $rx_time != $pre_rx_time) {
                    ## retransmission: timeout
                    print "  - retransmission\n" if($DEBUG3);
                    $pre_rx_time = $rx_time;

                    $inflight_pkt_bytes = $seq + $payload_len - $pre_ack + 1;
                    push(@inflight_pkt_bytes, $inflight_pkt_bytes);
                    
                    $sshresh_tahoe = $cwnd_tahoe / 2;
                    $sshresh_reno = $cwnd_reno / 2;
                    # $sshresh_tahoe = 1 * $MSS;
                    # $sshresh_reno = 1 * $MSS;
                    print "    - tahoe threshold: $sshresh_tahoe\n";
                    print "    - reno threshold : $sshresh_reno\n";
                    $cwnd_tahoe = $INIT_CWND;
                    $cwnd_reno = $INIT_CWND;

                    # push(@inflight_pkt_bytes, $inflight_pkt_bytes);
                    push(@cwnd_tahoe, $cwnd_tahoe);
                    push(@cwnd_reno, $cwnd_reno);

                    push(@rx_win, $rx_win);

                }
                elsif($seq < $pre_seq) {
                    ## re-ordering / retransmission
                    print "  - re-ordering\n" if($DEBUG3);

                    $pre_seq = $seq;
                    $pre_len = $payload_len;
                    $pre_rx_time = $rx_time;
                }
                else {
                    ## unknown
                    die "unknown \n";
                }
            }
            elsif($ack >= 0) {
                print "$this_ip - $this_conn: ACK , ack=$ack ($pre_ack), win=$win\n" if($DEBUG3);
                $num_rx_ack ++;

                if($ack > $pre_ack) {
                    $inflight_pkt_bytes = $pre_seq + $pre_len - $pre_ack + 1;
                    $pre_ack = $ack;

                    print "  - cwnd = $inflight_pkt_bytes\n" if($DEBUG3);
                    # print "  - tahoe = $cwnd_tahoe\n" if($DEBUG3);
                    # print "  - reno = $cwnd_reno\n" if($DEBUG3);
                    push(@inflight_pkt_bytes, $inflight_pkt_bytes);
                    # push(@cwnd_tahoe, $cwnd_tahoe);
                    # push(@cwnd_reno, $cwnd_reno);

                    if($cwnd_tahoe < $sshresh_tahoe) {
                        $cwnd_tahoe = min($rx_win, $cwnd_tahoe + $MSS);
                    }
                    else {
                        $cwnd_tahoe = min($rx_win, $cwnd_tahoe + $MSS * $MSS / $cwnd_tahoe);
                    }
                    if($cwnd_reno < $sshresh_reno) {
                        $cwnd_reno = min($rx_win, $cwnd_reno + $MSS);
                    }
                    else {
                        $cwnd_reno = min($rx_win, $cwnd_reno + $MSS * $MSS / $cwnd_reno);
                    }
                    # $inflight_pkt_bytes = $pre_seq + $pre_len - $pre_ack + 1;
                    # print "  - cwnd after = $inflight_pkt_bytes\n" if($DEBUG3);
                    print "  - tahoe = $cwnd_tahoe\n" if($DEBUG3);
                    print "  - reno = $cwnd_reno\n" if($DEBUG3);
                    # push(@inflight_pkt_bytes, $inflight_pkt_bytes);
                    push(@cwnd_tahoe, $cwnd_tahoe);
                    push(@cwnd_reno, $cwnd_reno);

                    $rx_win = $win;
                    print "  - win = $rx_win\n" if($DEBUG3);
                    push(@rx_win, $rx_win);

                    $num_dup_ack = 0;
                }
                else {
                    ## dup ack
                    $num_dup_ack ++;
                    print "  - dup ACK # $num_dup_ack\n" if($DEBUG3);
                    
                    if($num_dup_ack == 3) {
                        $sshresh_tahoe = $cwnd_tahoe / 2;
                        $sshresh_reno = $cwnd_reno / 2;
                        print "    - tahoe threshold: $sshresh_tahoe\n";
                        print "    - reno threshold : $sshresh_reno\n";
                        $cwnd_tahoe = $INIT_CWND;
                        $cwnd_reno = $sshresh_reno;

                        $inflight_pkt_bytes = $pre_seq + $pre_len - $pre_ack + 1;
                        print "  - cwnd = $inflight_pkt_bytes\n" if($DEBUG3);
                        print "  - tahoe = $cwnd_tahoe\n" if($DEBUG3);
                        print "  - reno = $cwnd_reno\n" if($DEBUG3);
                        push(@inflight_pkt_bytes, $inflight_pkt_bytes);
                        push(@cwnd_tahoe, $cwnd_tahoe);
                        push(@cwnd_reno, $cwnd_reno);

                        $rx_win = $win;
                        print "  - win = $rx_win\n" if($DEBUG3);
                        push(@rx_win, $rx_win);
                    }
                }
            }
            else{
                die "should be either tx data or rx ack\n";
            }
        }

        ## Check if the flow is valid
        ## b) > X tx data pkts
        if($num_tx_pkts <= $MIN_NUM_PKTS or $num_rx_ack < 1) {
            $num_flow_invalid_pkt ++;
        }
        else {
            $num_flows ++;
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{INFLIGHT_PKT_BYTES} }, @inflight_pkt_bytes);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TAHOE}              }, @cwnd_tahoe);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RENO}               }, @cwnd_reno);
            push(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_WIN}             }, @rx_win);
        }
    }
}


#####
## output
print STDERR "start to output..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{INFLIGHT_PKT_BYTES});

        open FH, "> $output_dir/$file_name.$this_ip.$this_conn.cwnd.txt";
        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{INFLIGHT_PKT_BYTES} })-1) {
            my $out = sprintf("%d, %f, %f, %d\n", 
                                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{INFLIGHT_PKT_BYTES}[$ind],
                                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TAHOE}[$ind],
                                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RENO}[$ind],
                                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_WIN}[$ind]);
            print FH "$out";
        }
        close FH;
    }
}





print "#flow, #invalid_pkt, #invalid_syn\n";
print "$num_flows, $num_flow_invalid_pkt, $num_flow_invalid_syn\n";
