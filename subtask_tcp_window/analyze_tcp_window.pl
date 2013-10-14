#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/08/12 @ Narus 
##
## analyze TCP receiving window 
##
## - input: parsed_pcap_text
##     a) tcp packets: text2
##      format
##      <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
##     b) tcp packets with window scale: text6
##      format
##      <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <window scale>
##
## - output
##     ./output/
##
##  e.g.
##      perl analyze_tcp_window.pl 49
##################################################

use strict;


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
# my $FIX_SRC_ADDR = "^10.";
# my $FIX_SRC_ADDR = "28.222.137.183";

my $NUM_FLOW = 2;
my $NUM_PKT  = 0;

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
open FH, "$file_name_tcp" or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len))."\n" if($DEBUG1);

    next if($FIX_SRC and !($src =~ /$FIX_SRC_ADDR/));
    next if($FIX_DST and !($dst =~ /$FIX_DST_ADDR/));

    ## check if it's a reordering / retransmission
    next if(exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ} and $seq < $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}[-1]);


    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SEQ}     }, $seq);
    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{WIN}     }, $win);
    push(@{ $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{RX_TIME} }, $time + $time_usec / 1000000);
    $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{INIT_WIN} = $win if($is_syn == 1);
    $ip_info{IP}{$src}{INIT_WIN}{$win} = 1 if($is_syn == 1);
    $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;
    $ip_info{IP}{$src}{TTL}{$ttl} = 1;
}
close FH;


print STDERR "start to read TCP Window Scale data..\n" if($DEBUG2);
open FH, "$file_name_win" or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <win scale>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $win_scale) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0; $win_scale += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len, $win_scale))."\n" if($DEBUG1);

    next if($FIX_SRC and !($src =~ /$FIX_SRC_ADDR/));
    next if($FIX_DST and !($dst =~ /$FIX_DST_ADDR/));


    $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{SCALE} = $win_scale if(exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"});
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
        next if(!exists $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{WIN});


        my ($tag, $val) = split(/: |\r/, $line);
        chomp $tag;
        chomp $val;
        print "    ($tag, $val)\n" if($DEBUG1);

        ## User-Agent
        if($tag =~ /User.*Agent/i) {
            print "^^^ $val\n" if($DEBUG1);
            $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{AGENT}{$val} = 1;
            # $ip_info{IP}{$src}{CONN}{"$s_port.$dst.$d_port"}{TTL}{$ttl} = 1;
            # $ip_info{IP}{$src}{TTL}{$ttl} = 1;
        }
    }


}
close FH;


#####
## Analyze
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        ## User Agents
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT});
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{INIT_WIN});
        foreach my $this_ua (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {
            
            ## OSs: Windows, Microsoft, Android, MAC
            foreach my $os_ind (0 .. @OS_keywords-1) {
                my $os_keyword = $OS_keywords[$os_ind];
                my $os         = $OSs[$os_ind];

                if($this_ua =~ /$os_keyword/i) {
                    $ip_info{IP}{$this_ip}{OS}{$os} = 1;
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS}{$os} = 1;
                    
                    last;
                }
            }
            

            ## device: HTC, Samsung, LGE, NOKIA, Windows Phone, iPhone, iPad, MacBookAir 
            foreach my $device_ind (0 .. @device_keywords-1) {
                my $device_keyword = $device_keywords[$device_ind];
                my $device         = $devices[$device_ind];

                if($this_ua =~ /$device_keyword/i) {
                    $ip_info{IP}{$this_ip}{DEVICE}{$device} = 1;
                    $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE}{$device} = 1;

                    last;
                }
            }
        }
    }
}


my @selected_ips = ();
my $cnt_valid_ip = 0;
my $tp = 0;
my $tn = 0;
my $fp = 0;
my $fn = 0;
print STDERR "start to analyze result..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    
    # num of flows / TTL / OS / devices / init win
    my $num_flow = scalar(keys %{ $ip_info{IP}{$this_ip}{CONN} });
    next if ($num_flow < $NUM_FLOW);
    my $num_ttl = 0;
    $num_ttl = scalar(keys %{ $ip_info{IP}{$this_ip}{TTL} }) if(exists $ip_info{IP}{$this_ip}{TTL});
    my $num_os = 0;
    $num_os = scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }) if(exists $ip_info{IP}{$this_ip}{OS});
    my $num_device = 0;
    $num_device = scalar(keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) if(exists $ip_info{IP}{$this_ip}{DEVICE});
    my $num_init_win = 0;
    $num_init_win = scalar(keys %{ $ip_info{IP}{$this_ip}{INIT_WIN} }) if(exists $ip_info{IP}{$this_ip}{INIT_WIN});
    print "$this_ip (#flows=$num_flow, #win=$num_init_win, #TTLs=$num_ttl, #os=$num_os, #device=$num_device): \n" if($DEBUG2);


    #####
    ## evaluation
    if($num_os == 1) {
        $cnt_valid_ip ++;

        if($num_init_win == 1) {
            $tn ++;
        }
        elsif($num_init_win > 1) {
            $fp ++;
        }
        else {
            die "# init win size should not be 0\n";
        }
    }
    elsif($num_os > 1) {
        $cnt_valid_ip ++;

        if($num_init_win == 1) {
            $fn ++;
        }
        elsif($num_init_win > 1) {
            $tp ++;
        }
        else {
            die "# init win size should not be 0\n";
        }
    }
    


    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN});
        next if(!exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{INIT_WIN});

        # num of pkts
        my $num_pkt = scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN} });
        if($num_pkt < $NUM_PKT) {
            $num_flow --;
            last if ($num_flow < $NUM_FLOW);
            next;
        }
        print "  - $this_conn ($num_pkt): \n" if($DEBUG2);
        

        my $this_scale = 1;
        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SCALE}) {
            $this_scale = 2 ** $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SCALE};
        }
        print "    - init win: ".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{INIT_WIN}."\n" if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{INIT_WIN});
        print "    - win [$this_scale]: ".join(",", (@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN} }))."\n" if($DEBUG2);


        ## TTL
        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL}) {
            print "    - TTL: ".join(", ", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} }))."\n" if($DEBUG2);
        }


        ## User Agents
        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT}) {
            foreach my $this_ua (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{AGENT} }) {
                print "    - Agent: $this_ua\n" if($DEBUG2);
                ## OSs: Windows, Microsoft, Android, MAC
                foreach my $os_ind (0 .. @OS_keywords-1) {
                    my $os_keyword = $OS_keywords[$os_ind];
                    my $os         = $OSs[$os_ind];

                    if($this_ua =~ /$os_keyword/i) {
                        print "    - OS: $os\n" if($DEBUG2);
                        $ip_info{IP}{$this_ip}{OS}{$os} = 1;

                        last;
                    }
                }


                ## device: HTC, Samsung, LGE, NOKIA, Windows Phone, iPhone, iPad, MacBookAir 
                foreach my $device_ind (0 .. @device_keywords-1) {
                    my $device_keyword = $device_keywords[$device_ind];
                    my $device         = $devices[$device_ind];

                    if($this_ua =~ /$device_keyword/i) {
                        print "    - Device: $device\n" if($DEBUG2);
                        $ip_info{IP}{$this_ip}{DEVICE}{$device} = 1;

                        last;
                    }
                }
            }
        }
    }

    if($num_flow >= $NUM_FLOW) {
        push(@selected_ips, $this_ip);
    }
}


#####
## output
foreach my $this_ip (@selected_ips) {
    open FH_FIG, ">$gnuplot_file" or die $!;
    print FH_FIG "reset\n";
    if($PLOT_EPS) {
        print FH_FIG "set terminal postscript enhanced\n";
    }
    else {
        print FH_FIG "set term pngcairo\n";
    }
    print FH_FIG "set size ratio 0.7\n";
    print FH_FIG "figure_dir = \"$figure_dir\"\n";
    print FH_FIG "data_dir = \"$output_dir\"\n";
    # print FH_FIG "set yrange [-0.01:0.01]\n";
    print FH_FIG "set xlabel \"Time\"\n";
    print FH_FIG "set ylabel \"win size\"\n";
    print FH_FIG "set key Left under reverse nobox spacing 2\n";
    print FH_FIG "set xtics rotate by 315\n";

    # print FH_FIG "set style line 1 lc rgb \"#FF0000\" ps 2 pt 3 lt 1 lw 3\n";
    print FH_FIG "set style line 1 lc rgb \"#FF0000\" ps 1 lw 3\n";
    print FH_FIG "set style line 2 lc rgb \"#0000FF\" ps 1 lw 3\n";
    print FH_FIG "set style line 3 lc rgb \"orange\" ps 1 lw 3\n";
    print FH_FIG "set style line 4 lc rgb \"green\" ps 1 lw 3\n";
    print FH_FIG "set style line 5 lc rgb \"yellow\" ps 1 lw 3\n";
    print FH_FIG "set style line 6 lc rgb \"black\" ps 1 lw 3\n";
    print FH_FIG "set style line 7 lc rgb \"#FF0000\" ps 1 lw 3\n";
    print FH_FIG "set style line 8 lc rgb \"#0000FF\" ps 1 lw 3\n";
    print FH_FIG "set style line 9 lc rgb \"orange\" ps 1 lw 3\n";
    print FH_FIG "set style line 10 lc rgb \"green\" ps 1 lw 3\n";
    print FH_FIG "set style line 11 lc rgb \"yellow\" ps 1 lw 3\n";
    print FH_FIG "set style line 12 lc rgb \"black\" ps 1 lw 3\n";

    if($PLOT_EPS) {
        print FH_FIG "set output figure_dir.\"\/$file_name.$this_ip.win.eps\"\n";
    }
    else {
        print FH_FIG "set output figure_dir.\"\/$file_name.$this_ip.win.png\"\n";
    }
    print FH_FIG "plot ";


    my $cnt = 0;
    foreach my $this_conn (keys %{ $ip_info{IP}{$this_ip}{CONN} }) {
        my $os = "";
        $os = join(",", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS} })) if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{OS});
        my $device = "";
        $device = join(",", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE} })) if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{DEVICE});
        my $ttl = "";
        $ttl = join(",", (keys %{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL} })) if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{TTL});
        my $this_scale = 1;
        if(exists $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SCALE}) {
            $this_scale = 2 ** $ip_info{IP}{$this_ip}{CONN}{$this_conn}{SCALE};
        }

        
        my $file_output = "$file_name.$this_ip.$this_conn.txt";
        open FH, "> $output_dir/$file_output" or die $!;
        foreach my $ind (0 .. scalar(@{ $ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN} })-1) {
            print FH "".$ip_info{IP}{$this_ip}{CONN}{$this_conn}{RX_TIME}[$ind].", ".($ip_info{IP}{$this_ip}{CONN}{$this_conn}{WIN}[$ind] * $this_scale)."\n";
        }
        close FH;

        print FH_FIG ", \\\n" if($cnt != 0);
        my $line_cnt = ($cnt % 12) + 1;
        $cnt ++;
        print FH_FIG "data_dir.\"\/$file_name.$this_ip.$this_conn.txt\" using 1:2 with linespoints ls $line_cnt title \"OS=[$os],Device=[$device],TTL=[$ttl]\"";
    }

    close FH_FIG;
    my $cmd = "gnuplot $gnuplot_file";
    `$cmd`;
}





print "valid, tp, tn, fp, fn\n";
print "$cnt_valid_ip, $tp, $tn, $fp, $fn\n";
