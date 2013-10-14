#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/20 @ Narus
##
## Compare the result of User Agent and TTL heuristic
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
##     e) FIX_DS T  : only target the pkts to some destination node
##     f) THRESHOLD : only IP with # of pkts > THRESHOLD will be analyzed
##
##  e.g.
##      perl user_agent_vs_ttl.pl 49
##      perl user_agent_vs_ttl.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
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
my $DEBUG4 = 1; ## print false cases

my $FIX_FREQ       = 1; ## fix frequency
my $PLOT_EPS       = 1; ## 1 to output eps; 0 to output png figure
my $PLOT_LOGX      = 0; ## 1 to plot log x; 0 otherwise
my $PLOT_TIMESTAMP = 0; ## 1 to plot received time v.s. Timestamp -- not very useful

my $FIX_DST       = 0; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
my $FIX_DST_ADDR  = "192.168.5.67";
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
my $BOOT_TIME_SPAN_THRESHOLD = 3;  ## the boot time interval between packets should be smaller than this threshold

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux", "Xbox");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");
my @devices         = ("HTC", "Samsung", "Samsung",  "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox");

my @MAJOR_TTLS = (63, 127);

#####
## variables
my $input_dir_ts  = "/data/ychen/sprint/text5";
my $input_dir_ua  = "/data/ychen/sprint/text3";
my $input_dir_tcp = "/data/ychen/sprint/text2";
my $output_dir = "./output_statistics";
my $figure_dir = "./figure_statistics";
my $gnuplot_file = "plot_freq.plot";

my $file_name;
my $file_name_ts;
my $file_name_ua;
my $file_name_tcp;
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
    $file_name_ts  = "$input_dir_ts/$file_name";
    $file_name_ua  = "$input_dir_ua/$file_name";
    $file_name_tcp = "$input_dir_tcp/$file_name";
}
else {
    $file_name = $ARGV[0];
    $file_name_ts  = "/data/ychen/testbed/tcp_traces/text5/$file_name";
    $file_name_ua  = "/data/ychen/testbed/tcp_traces/text3/$file_name";
    $file_name_tcp = "/data/ychen/testbed/tcp_traces/text2/$file_name";
    if(! -e $file_name_ts) {
        $file_name_ts  = "/data/ychen/testbed/3g_measurement/text5/$file_name";
        $file_name_ua  = "/data/ychen/testbed/3g_measurement/text3/$file_name";
        $file_name_tcp = "/data/ychen/testbed/3g_measurement/text2/$file_name";
    }
}
$iteration = $ARGV[1] + 0;
print "input file name = $file_name_ts\n" if($DEBUG2);
print "input file name = $file_name_ua\n" if($DEBUG2);
print "input file name = $file_name_tcp\n" if($DEBUG2);


####################################################
## Iterations
####################################################
if($iteration == 0) {
    @MAJOR_TTLS = (60..68, 90..100, 120..128, 250..256);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}
elsif($iteration == 1) {
    @MAJOR_TTLS = (63, 127);
    @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox", "iPad", "iPhone", "MacBookAir", "LGE", "HTC", "Samsung");
    @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox", "Apple", "Apple", "Apple", "Android", "Android", "Android");
}




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
            
            ## get OS
            my @tmp_ua = ($val);
            my @os = Tethering::_identify_os(\@tmp_ua, \@OS_keywords, \@OSs);

            if(scalar(@os) == 1) { 
                $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{AGENT}{$val} = 1;
                $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TTL}{$ttl} = 1;
                $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{UA_OS} = $os[0];
            }
        }
    }
}
close FH;

if($DEBUG1) {
    print "-------------------------------------\n";
    foreach my $this_ip (keys %{ $ip_info{IP} }) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            print "$this_ip -- $this_conn: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{UA_OS}."\n";
        }
    }
    print "=====================================\n";
}
if($DEBUG1) {
    print STDERR "before read TCP: ".scalar(keys %{ $ip_info{IP} })."\n";
}


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
    

    ## skip flows without user agent
    if(!exists($ip_info{IP}{$src})) {
        next;
    }
    if(!exists($ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"})) {
        # print "$src -- $s_port:$dst:$d_port not exists\n";
        next;
    }
    # if($ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{UA_OS} eq "") {
    #     print "$src -- $s_port:$dst:$d_port exists\n";
    #     print "no os\n";
    #     next;
    # }
    # print "$src -- $s_port:$dst:$d_port exists\n";
    # print "os=\"".$ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{UA_OS}."\"\n";
    
    if(exists $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}) {
        ## disorder
        next if($seq <= $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}[-1]);
        ## skip duplicate packets (seq and rx time are the same)
        next if($seq == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}[-1] and 
                ($time + $time_usec / 1000000) == $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}[-1]);
    }

    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{SEQ}         }, $seq);
    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{RX_TIME}     }, $time + $time_usec / 1000000);
    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{ID}          }, $id);
    # $ip_info{IP}{$src}{CONN}{"$s_port:$dst:$d_port"}{TTL}{$ttl} = 1;
}
close FH;
if($DEBUG1) {
    print STDERR "before read TCP: ".scalar(keys %{ $ip_info{IP} })."\n";
}


if($DEBUG1) {
    print "=====================================\n";
    foreach my $this_ip (keys %{ $ip_info{IP} }) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            print "$this_ip -- $this_conn: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{UA_OS}."\n";
        }
    }
    print "#####################################\n";
}


############################################################
## Calculate boot time and identify OS
############################################################
print STDERR "start to Calculate boot time and identify OS..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {

    #################################
    ## Flow:
    ##   IP - Flow |- TTL
    ##             |- User_Agent
    ##             |- OS
    ##
    ## TTL:
    ##   IP - TTL - OS
    ##
    ## OS:
    ##   IP - OS - TTL
    ##
    print "------------------------------\n" if($DEBUG3);
    die if(!exists($ip_info{IP}{$this_ip}{CONN}));

    my $has_ttl64 = 0;
    my $ttl64_no_os = 1;
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        print "$this_ip -- $this_conn: \n" if($DEBUG3);

        # ## OS of the flow by UA
        my $os = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{UA_OS};
        print "  - UA OS: $os\n" if($DEBUG3);
        # $ip_info{IP}{$this_ip}{UA_OS}{$os} = () if(!exists $ip_info{IP}{$this_ip}{UA_OS}{$os});
        # print "  - UA: $os\n" if($DEBUG3);

        ## TTL of the flow
        foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
            ## OS
            $ip_info{IP}{$this_ip}{UA_OS}{$os}{TTL}{$this_ttl} = 1;
            ## TTL
            $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{UA_OS}{$os} = 1 ;    
        }

        ## OS of the flow by TTL and ID
        foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
            print "  - TTL: $this_ttl\n" if($DEBUG3);
            ## Android, iOS, or some Windows
            if($this_ttl == 64 or $this_ttl == 63 or $this_ttl == 62 or $this_ttl == 61) {
                $has_ttl64 = 1;
                # $ip_info{IP}{$this_ip}{IP_OS}{"Android"} = 1;
                my $cnt_violation = 0;
                my $cnt_well_increase = 0;
                my $cnt_pkt = (@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID} }) - 1;
                foreach my $ind (1 .. $cnt_pkt) {
                    if( ## IP ID decrease
                        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind] <
                        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind-1] and 
                        ## not wrap around
                        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind-1] < 65000) {
                        
                        $cnt_violation ++;
                    }

                    if( ($ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind] - 
                        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind-1]) < 5 and 
                        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind] >= 
                        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind-1]) {

                        $cnt_well_increase ++;
                    }

                    print "  >> ".($ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind] - 
                        $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID}[$ind-1])."\n";
                }
                
                if($cnt_pkt > 3 and ($cnt_well_increase / $cnt_pkt) >= 0.8) {
                    $ttl64_no_os = 0;
                    $ip_info{IP}{$this_ip}{IP_OS}{"Android"} = 1;
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{IP_OS} = "Android";

                    print "    - IP: Android = $cnt_well_increase / $cnt_pkt >= 0.8\n" if($DEBUG3);
                }
                elsif($cnt_pkt < 10) {
                    ## only have 1 packet..
                    # $ip_info{IP}{$this_ip}{IP_OS}{"Android"} = 1;

                    
                }
                elsif( ($cnt_violation / $cnt_pkt) < 0.1) {
                    $ttl64_no_os = 0;
                    $ip_info{IP}{$this_ip}{IP_OS}{"Android"} = 1;
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{IP_OS} = "Android";

                    print "    - IP: Android = $cnt_violation / $cnt_pkt < 0.1\n" if($DEBUG3);
                }
                else {
                    $ttl64_no_os = 0;
                    $ip_info{IP}{$this_ip}{IP_OS}{"Apple"} = 1;
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{IP_OS} = "Apple";

                    print "    - IP: Apple = $cnt_violation / $cnt_pkt >= 0.1\n" if($DEBUG3);
                }
                print "      - ".join(",", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID} })."\n";
                print "      - ".join(",", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SEQ} })."\n";
                print "      - ".join(",", @{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME} })."\n";
            }

            ## Windows
            elsif($this_ttl == 128 or $this_ttl == 127 or $this_ttl == 126 or $this_ttl == 125) {
                $ip_info{IP}{$this_ip}{IP_OS}{"Windows"} = 1;
                $ip_info{IP}{$this_ip}{CONN}{$this_conn}{IP_OS} = "Windows";

                print "    - IP: Windows\n" if($DEBUG3);
            }

            else {
                ## unknown
                # $ip_info{IP}{$this_ip}{IP_OS}{"Android"} = 1;
            }
        }
    }

    if($has_ttl64 == 1 && $ttl64_no_os == 1) {
        $ip_info{IP}{$this_ip}{IP_OS}{"Android"} = 1;
        # $ip_info{IP}{$this_ip}{CONN}{$this_conn}{IP_OS} = "Android";

        print "    > IP: Android\n" if($DEBUG3);
    }
}




############################################################
## Evaluate results
############################################################
## Flow:
##   IP |- Flow |- TTL
##      |       |- User_Agent
##      |       |- OS
##      |- UA_OS
##      |- IP_OS
##
print STDERR "start to Evaluate results..\n" if($DEBUG2);
my $cnt_ip = 0;
my $cnt_invalid_ip = 0;
my $tp = 0;
my $tn = 0;
my $fp = 0;
my $fn = 0;

print "\n-- Evaluation -------------------------------\n" if($DEBUG4);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    my $num_ua_os = scalar(keys %{ $ip_info{IP}{$this_ip}{UA_OS} });
    # my $num_ttl   = scalar(keys %{ $ip_info{IP}{$this_ip}{TTL} });
    my $num_ttl = scalar(keys %{ $ip_info{IP}{$this_ip}{IP_OS} });


    ## True Positive
    if($num_ua_os >= 2 and $num_ttl >= 2) {
    # if($num_ua_os >= 2 and $num_ip_os >= 2) {
        $cnt_ip ++;
        $tp ++;
    }
    ## True Negative
    elsif($num_ua_os <= 1 and $num_ttl <= 1) {
    # elsif($num_ua_os <= 1 and $num_ip_os <= 1) {
        $cnt_ip ++;
        $tn ++;
    }
    ## False Positive
    elsif($num_ua_os <= 1 and $num_ttl >= 2) {
    # elsif($num_ua_os <= 1 and $num_ip_os >= 2) {
        $cnt_ip ++;
        $fp ++;
        
        if($DEBUG4) {
            print "False Positive\n";
            print "  - $this_ip\n";
            print "    - UA: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{UA_OS} }) )."\n";
            print "    - IP: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{IP_OS} }) )."\n";
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) { 
                print "      - $this_conn\n";
                print "        - UA: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }))."\n";
                print "        - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }))."\n";
                print "        - ID: ".join(", ", (@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID} }))."\n";
                print "        - IP OS: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{IP_OS}."\n";
            }
        }
    }
    ## False Negative
    elsif($num_ua_os >= 2 and $num_ttl <= 1) {
    # elsif($num_ua_os >= 2 and $num_ip_os <= 1) {
        $cnt_ip ++;
        $fn ++;


        if($DEBUG4) {
            print "False Negative\n";
            print "  - $this_ip\n";
            print "    - UA: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{UA_OS} }) )."\n";
            print "    - IP: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{IP_OS} }) )."\n";
            foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) { 
                print "      - $this_conn\n";
                print "        - UA: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }))."\n";
                print "        - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }))."\n";
                print "        - ID: ".join(", ", (@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{ID} }))."\n";
                print "        - IP OS: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{IP_OS}."\n";
            }
        }
    }
}


############################################################
## Output
############################################################
print STDERR "start to generate output..\n" if($DEBUG2);
open FH, ">> $output_dir/user_agent_vs_ttl_id.$iteration.txt" or die $!;
print FH "$cnt_ip, $tp, $tn, $fp, $fn\n";
close FH;

print "\n valid_ip, invalid_ip, tp, tn, fp, fn\n";
print "$cnt_ip, $cnt_invalid_ip, $tp, $tn, $fp, $fn\n";
print STDERR "$cnt_ip, $cnt_invalid_ip, $tp, $tn, $fp, $fn\n";

