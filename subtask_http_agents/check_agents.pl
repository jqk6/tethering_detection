#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/24 @ Narus 
##
## check all the agents from http server
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
##     <http header>
##     <new line>
##
## - output
##      print out agents of each user
##
##  e.g.
##      perl check_agents.pl /data/ychen/sprint/text3/omni.out.49.eth.pcap.txt
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

my %ip_info;        ## ip pair seq and ack info
                    ## {SRC}{src ip}{AGENT}{agent}{TIME}



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
            $ip_info{IP}{$src}{AGENT}{$val}{TIME} = $time + $time_usec / 1000000;
        }
    }


}
close FH;


#####
## Output
print STDERR "start to print result..\n" if($DEBUG2);
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    print $this_ip.": (".scalar(keys %{ $ip_info{IP}{$this_ip}{AGENT} }).")\n";

    foreach my $this_agents (keys %{ $ip_info{IP}{$this_ip}{AGENT} }) {
        print "   - ".$this_agents."\n";
    }
    print "\n";
}