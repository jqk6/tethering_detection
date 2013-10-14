#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/19 @ Narus
##
## Modified from user_agent_vs_ttl.pl. Used to get the statistics about the cause of FP, FN
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
##      perl user_agent_vs_ttl_statistics.pl 49
##      perl user_agent_vs_ttl_statistics.pl 2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt
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
my $output_dir = "./output_statistics";
my $figure_dir = "./figure_statistics";
my $gnuplot_file = "plot_freq.plot";

my $file_name;
my $file_name_ts;
my $file_name_ua;
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
        next if($FIX_SRC  and (!($src =~ /$FIX_SRC_ADDR/ )));
        next if($FIX_DEST and (!($dst =~ /$FIX_DEST_ADDR/)));


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
                $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{AGENT}{$val} = 1;
                $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;
                $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{OS} = $os[0];
            }
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
    if(exists($ip_info{IP}{$this_ip}{CONN})) {
        foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
            print "$this_ip -- $this_conn: \n" if($DEBUG3);

            ## OS of the flow
            my $os = $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS};
            
            ## TTL of the flow
            foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }) {
                ## OS
                $ip_info{IP}{$this_ip}{OS}{$os}{TTL}{$this_ttl} = 1;
                ## TTL
                $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{OS}{$os} = 1 ;    
            }
        }
    }
}




############################################################
## Evaluate results
############################################################
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
print STDERR "start to Evaluate results..\n" if($DEBUG2);
my $cnt_ip = 0;
my $cnt_invalid_ip = 0;
my $tp = 0;
my $tn = 0;
my $fp = 0;
my $fn = 0;

my $fp_path = 0;    ## e.g. (63, 64), (125, 127)
my $fp_path_win = 0;    ## e.g. 63, 64 and is windows
my $fp_win_63_127 = 0;    ## e.g. 63, 64
my $fp_wierd_ttl = 0; ## e.g. not 63, 127
my $fn_non_win = 0; ## 2 OS are both non-windows

print "\n-- Evaluation -------------------------------\n" if($DEBUG4);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    my $num_os = scalar(keys %{ $ip_info{IP}{$this_ip}{OS} });
    my $num_ttl = scalar(keys %{ $ip_info{IP}{$this_ip}{TTL} });


    ## True Positive
    if($num_os >= 2 and $num_ttl >= 2) {
        $cnt_ip ++;
        $tp ++;
    }
    ## True Negative
    elsif($num_os <= 1 and $num_ttl <= 1) {
        $cnt_ip ++;
        $tn ++;
    }
    ## False Positive
    elsif($num_os <= 1 and $num_ttl >= 2) {
        $cnt_ip ++;
        $fp ++;

        ## cause analysis
        ## i) multiple path
        my $max_ttl = -1;
        my $min_ttl = 256;
        foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{TTL} }) {
            $max_ttl = $this_ttl if($max_ttl < $this_ttl);
            $min_ttl = $this_ttl if($min_ttl > $this_ttl);
        }
        if(($max_ttl - $min_ttl) <= 2) {
            $fp_path ++;

            my @tmp_os = (keys %{ $ip_info{IP}{$this_ip}{OS} });
            if($tmp_os[0] eq "Windows") {
                $fp_path_win ++;
            }
        }
        ## ii) wierd ttl
        foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{TTL} }) {
            my $found = 0;
            foreach my $nor_ttl (@MAJOR_TTLS) {
                if($this_ttl == $nor_ttl) {
                    $found = 1;
                    last;
                }
            }
            if($found == 0) {
                $fp_wierd_ttl ++;
                last;
            }
        }
        ## iii) windows could have 63 or 127
        foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
            if($this_os eq "Windows" and scalar(keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{TTL} }) > 1) {
                my @ttls = sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{TTL} });
                my $ttl1 = $ttls[0];
                my $ttl2 = $ttls[1];
                
                if($ttl1 == 63 and $ttl2 == 127) {
                    $fp_win_63_127 ++;
                    last;
                }
            }
        }
        
        if($DEBUG4) {
            print "False Positive\n";
            print "  - $this_ip\n";
            if(exists $ip_info{IP}{$this_ip}{OS}) {
                foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                    print "    - OS view\n";
                    print "      OS: $this_os\n";
                    print "      TTLs: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{TTL} }))."\n";
                }
            }
            if(exists $ip_info{IP}{$this_ip}{TTL}) {
                foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{TTL} }) {
                    print "    - TTL view\n";
                    print "      TTL: $this_ttl\n";
                    print "      OSs: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{OS} }))."\n";
                }
            }
        }
    }
    ## False Negative
    elsif($num_os >= 2 and $num_ttl <= 1) {
        $cnt_ip ++;
        $fn ++;


        ## cause analysis
        ## i) all OS are non-windows
        my $has_win = 0;
        foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
            if($this_os eq "Windows") {
                $has_win = 1;
                last;
            }
        }
        if($has_win == 0) {
            $fn_non_win ++;
        }
        

        if($DEBUG4) {
            print "False Negative\n";
            print "  - $this_ip\n";
            if(exists $ip_info{IP}{$this_ip}{OS}) {
                foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
                    print "    - OS view\n";
                    print "      OS: $this_os\n";
                    print "      TTLs: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{OS}{$this_os}{TTL} }))."\n";
                }
            }
            if(exists $ip_info{IP}{$this_ip}{TTL}) {
                foreach my $this_ttl (keys %{ $ip_info{IP}{$this_ip}{TTL} }) {
                    print "    - TTL view\n";
                    print "      TTL: $this_ttl\n";
                    print "      OSs: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{TTL}{$this_ttl}{OS} }))."\n";
                }
            }
            print "    - cause: have windows = $has_win\n"; ## 0 - no windows
        }
    }
}


############################################################
## Output
############################################################
print STDERR "start to generate output..\n" if($DEBUG2);
open FH, ">> $output_dir/user_agent_vs_ttl.statistics.$iteration.txt" or die $!;
print FH "$cnt_ip, $tp, $tn, $fp, $fn, $fp_path, $fp_path_win, $fp_win_63_127, $fp_wierd_ttl, $fn_non_win, ".($fn-$fn_non_win)."\n";
close FH;

print "\n valid_ip, invalid_ip, tp, tn, fp, fn, fp_path, fp_path_win, fp_win_63_127, fp_wierd_ttl, fn_non_win, fn_63_win\n";
print "$cnt_ip, $cnt_invalid_ip, $tp, $tn, $fp, $fn, $fp_path, $fp_path_win, $fp_win_63_127, $fp_wierd_ttl, $fn_non_win, ".($fn-$fn_non_win)."\n";


