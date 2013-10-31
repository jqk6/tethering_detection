#!/bin/perl

use strict;

srand(20);
my $base_shift = 604800; ## a week
my $cmd;

my $exp = 0;
my $tr  = 0;
my $shift;
my $discard;
my $dir = "../data/testbed/tcp_traces/text5";


###############################
## exp 0
if(0) {
    $exp = 0;
    $tr  = 0;
    $shift;
    $discard;
    $dir = "../data/testbed/tcp_traces/text5";


    ## non tethering
    print "- non tethering\n";
    my $ip_cnt = 1;
    while($ip_cnt < 200) {
        print "  - $ip_cnt\n";

        $shift = int(rand($base_shift));


        $tr ++;
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr 0 10.0.2.5 1.1.1.$ip_cnt $shift";
        `$cmd`;
        $ip_cnt ++;


        $tr ++;
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr 0 10.0.2.1 1.1.1.$ip_cnt $shift";
        `$cmd`;
        $ip_cnt ++;
    }

    ## tethering
    print "- tethering\n";
    while($ip_cnt < 250) {
        print "  - $ip_cnt\n";

        $tr ++;
        $shift = int(rand($base_shift));
        $discard = int(rand(20));
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr $discard 10.0.2.5 1.1.1.$ip_cnt $shift";
        `$cmd`;

        $tr ++;
        $shift = int(rand($base_shift));
        $discard = int(rand(20));
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr $discard 10.0.2.5 1.1.1.$ip_cnt $shift ";
        `$cmd`;

        $tr ++;
        $shift = int(rand($base_shift));
        $discard = int(rand(20));
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr $discard 10.0.2.5 1.1.1.$ip_cnt $shift ";
        `$cmd`;

        $ip_cnt ++;
    }
}


###############################
## exp 0
if(1) {
    $exp = 0;
    $tr  = 0;
    $shift;
    $discard;
    $dir = "../data/testbed/tcp_traces/text5";


    ## non tethering
    print "- non tethering\n";
    my $ip_cnt = 1;
    while($ip_cnt < 200) {
        print "  - $ip_cnt\n";

        $shift = int(rand($base_shift));


        $tr ++;
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr 0 10.0.2.5 1.1.1.$ip_cnt $shift";
        `$cmd`;
        $ip_cnt ++;


        $tr ++;
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr 0 10.0.2.1 1.1.1.$ip_cnt $shift";
        `$cmd`;
        $ip_cnt ++;
    }

    ## tethering
    print "- tethering\n";
    while($ip_cnt < 250) {
        print "  - $ip_cnt\n";

        $tr ++;
        $shift = int(rand($base_shift));
        $discard = int(rand(20));
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr $discard 10.0.2.5 1.1.1.$ip_cnt $shift";
        `$cmd`;

        $tr ++;
        $shift = int(rand($base_shift));
        $discard = int(rand(20));
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr $discard 10.0.2.5 1.1.1.$ip_cnt $shift ";
        `$cmd`;

        $tr ++;
        $shift = int(rand($base_shift));
        $discard = int(rand(20));
        $cmd = "perl gen_trace.pl $dir/2013.07.11.HTC.iperf.2min.pcap.txt $exp $tr $discard 10.0.2.5 1.1.1.$ip_cnt $shift ";
        `$cmd`;

        $ip_cnt ++;
    }
}
