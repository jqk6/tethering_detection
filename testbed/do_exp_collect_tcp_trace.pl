#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/07/08 @ Narus
##
## Collect pcap dump trace for clock skewing analysis:
##	Send HTTP request by calling "wget" to the specific machines and use "tshark" to collect pcap trace.
##
## - input
##		a) output file name: file_name
##		b) interface
##
## - output
##     ./tcp_traces/pcap
##     file_name.pcap:
##
## - interal variables
##     a) targets      : the servers to send HTTP requests.
##	   b) req_interval : the avg. HTTP request sending interval
##	   c) req_length   : the period of time (in seconds) to collect pcap trace
##
##  e.g.
##      perl do_exp_collect_tcp_trace.pl 2013.07.08.4utmachines eth0
##################################################

use strict;

use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug


#####
## variables
my $output_dir = "./tcp_traces/pcap";

my $file_name;
my $interface;

my $req_length   = 120;
my $req_interval = 0.5;
my $req_cnt 	 = $req_length / $req_interval;
# my @targets = ("zion.cs.utexas.edu", "valleyview.cs.utexas.edu", 
# 				"clockwork-grapefruit.cs.utexas.edu", "aero.cs.utexas.edu", 
# 				"caramello.cs.utexas.edu", "payday.cs.utexas.edu",
# 				"vermincelli.cs.utexas.edu", "totenberg.cs.utexas.edu",
# 				"smarties.cs.utexas.edu", "singh.cs.utexas.edu",
# 				"pinkwater.cs.utexas.edu", "mounds.cs.utexas.edu");
# my @targets = ("zion.cs.utexas.edu", "valleyview.cs.utexas.edu", 
# 				"pinkwater.cs.utexas.edu", "mounds.cs.utexas.edu");
my @targets = ("www.cs.utexas.edu", "linux1.csie.ntu.edu.tw", 
			   "www.stanford.edu", "www.mit.edu",
			   "www.nyu.edu", "www.ucla.edu",
			   "www.usc.edu", "www.berkeley.edu",
			   "www.northwestu.edu", "www.colorado.edu",
			   "www.uchicago.edu", "www.washington.edu",
			   "www.umich.edu", "illinois.edu",
			   "www.umn.edu", "www.miami.edu",
			   "www.sjtu.edu.cn", "www.u-tokyo.ac.jp",
			   "www.korea.edu", "www.pku.edu.cn",
			   "www.uni-heidelberg.de", "www.cam.ac.uk",
			   "www.ox.ac.uk", "sydney.edu.au");
## 128.83.120.139, 140.112.30.32
## 171.67.215.200, 23.200.70.151
## 128.122.119.202, 128.97.27.37
## 128.125.253.146, 169.229.216.200
## 70.97.96.63, 128.138.129.98
## 198.101.129.15, 128.95.155.198
## 141.211.13.226, 128.174.180.122
## 134.84.119.107, 129.171.32.100
## 202.120.2.102, 59.106.161.29
## 222.122.39.176, 162.105.131.113
## 129.206.13.27, 131.111.150.25
## 163.1.60.42, 129.78.5.11

#####
## check input
if(@ARGV != 2) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
$interface = $ARGV[1];
print "input file = $file_name\n" if($DEBUG1);
print "network interface = $interface\n" if($DEBUG1);



#####
## main starts here
my $cmd = "tshark -a duration:$req_length -i $interface -w $output_dir/$file_name.pcap &";
print $cmd."\n" if($DEBUG1);
system("$cmd");

my @t0 = gettimeofday();
my @t2 = gettimeofday();
foreach my $this_cnt (1 .. $req_cnt) {
	my @t1 = gettimeofday();
	my $elapsed = tv_interval( \@t0, \@t1 );
	print "$this_cnt: $elapsed\n" if($DEBUG2);
	@t0 = gettimeofday();

	foreach my $this_target (@targets) {
		# my $cmd = "ping $this_target -c $req_cnt -i $req_interval > /dev/null &";
		my $cmd = "curl $this_target/~yichao/index.html &> /dev/null &";
		print $cmd."\n" if($DEBUG1);
		system("$cmd");
	}


	## sleep
	my $sleep_time = $req_interval + rand(0.1) - 0.05;
	print "  sleep: $sleep_time\n" if($DEBUG2);
	usleep $sleep_time * 1000000;
}

my @t3 = gettimeofday();
my $elapsed = tv_interval( \@t2, \@t3 );
print "\ntotal elapsed time: $elapsed\n" if($DEBUG2);

