#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/24 @ Narus 
##
## Search HTTP User-Agent for the OS and device of the following keywords
##  OS: Windows, Microsoft, Android, MAC, Ubuntu
##  device: HTC, Samsung, LGE, NOKIA, Windows Phone, iPhone, iPad, MacBookAir 
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
##     <http header>
##     <new line>
##
## - output
##      ./output
##      file.<file id>.user_agent.txt
##      <ip> <# OSs> <# devices> <OS1> <OS2> ... <device1> <device2> ...
##
##  e.g.
##      perl analyze_sprint_http_user_agents.pl /data/ychen/sprint/text3/omni.out.49.eth.pcap.txt
##################################################

use strict;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug


#####
## variables
my $output_dir = "./output";

my $file_name;
my $file_id;

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux");
my @device_keywords = ("HTC", "Samsung", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir");
my @devices         = ("HTC", "Samsung", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir");

my %ip_info;        ## ip pair seq and ack info
                    ## {SRC}{src ip}{AGENT}{agent}
                    ## {SRC}{src ip}{OS}
                    ## {SRC}{src ip}{DEVICE}




#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
print "input file = $file_name\n" if($DEBUG1);
my @dir_structure = split(/\//, $file_name);
$file_id = $1+0 if(pop(@dir_structure) =~ /(\d+)/);
print "file id: $file_id\n" if($DEBUG1);


#####
## main starts here
print STDERR "start to read data..\n" if($DEBUG2);
open FH, "$file_name" or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    print "> $_" if($DEBUG1);
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len))."\n" if($DEBUG1);


    my $line = <FH>;
    print ">>> $line" if($DEBUG1);
    while($line = <FH>) {
        print ">>> $line" if($DEBUG1);
        last if($line eq "\n");

        my ($tag, $val) = split(/: |\r/, $line);
        chomp $tag;
        chomp $val;
        print "    ($tag, $val)\n" if($DEBUG1);

        ## User-Agent
        if($tag =~ /User.*Agent/i) {
            print "^^^ $val\n" if($DEBUG1);
            $ip_info{IP}{$src}{AGENT}{$val} = 1;
        }
    }


}
close FH;


#####
## Analyze the OS and device listed in User-Agent
print STDERR "start to search OS and device keywords..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    print $this_ip.": (".scalar(keys %{ $ip_info{IP}{$this_ip}{AGENT} }).")\n" if($DEBUG2);

    foreach my $this_agents (keys %{ $ip_info{IP}{$this_ip}{AGENT} }) {
        print "   - ".$this_agents."\n"  if($DEBUG2);


        ## OSs: Windows, Microsoft, Android, MAC
        foreach my $os_ind (0 .. @OS_keywords-1) {
            my $os_keyword = $OS_keywords[$os_ind];
            my $os         = $OSs[$os_ind];

            if($this_agents =~ /$os_keyword/i) {
                $ip_info{IP}{$this_ip}{OS}{$os} = 1;

                print "    >> $os\n" if($DEBUG2);
                
                last;
            }
        }
        

        ## device: HTC, Samsung, LGE, NOKIA, Windows Phone, iPhone, iPad, MacBookAir 
        foreach my $device_ind (0 .. @device_keywords-1) {
            my $device_keyword = $device_keywords[$device_ind];
            my $device         = $devices[$device_ind];

            if($this_agents =~ /$device_keyword/i) {
                $ip_info{IP}{$this_ip}{DEVICE}{$device} = 1;

                print "    >> $device\n" if($DEBUG2);

                last;
            }
        }
        
    }
    print "\n" if($DEBUG2);
}



#####
## Output
print STDERR "start to print result..\n" if($DEBUG2);
my $file_output = "file.$file_id.user_agent.txt";
open FH, "> $output_dir/$file_output" or die $!;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    print FH "$this_ip, ".scalar(keys %{ $ip_info{IP}{$this_ip}{OS} }).", ".scalar(keys %{ $ip_info{IP}{$this_ip}{DEVICE} }).", ";

    foreach my $this_os (keys %{ $ip_info{IP}{$this_ip}{OS} }) {
        print FH $this_os.", ";
    }
    foreach my $this_device (keys %{ $ip_info{IP}{$this_ip}{DEVICE} }) {
        print FH $this_device.", ";
    }
    print FH "\n";
}
close FH;



