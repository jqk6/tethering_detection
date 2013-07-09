#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/14 @ Narus 
##
## Read IPs of tethered clients detected by different methods, and validate the overlapping
##
## - input: 
##     ./tethered_clients/
##     IP of tethered clients.
##      Possible base:
##      a) TTL (whole trace)         : TTL_whole_trace.<file id>.txt
##      b) TTL (one second)          : TTL_one_second.<file id>.txt
##      c) TTL (default value)       : TTL_default_value.<file id>.txt
##      d) User Agent                : User_agent.<file id>.txt
##      e) TTL (diff)                : TTL_diff.<file id>.txt
##
##      Evaluation Methods
##      a) Connections               : Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 5, 10, 60, 600)
##                                     Thresholds = (2 .. 30)
##      b) RTT (variance)            : RTT_variance.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, .. , 0.8)
##      c) Inter-arrival time (mean) : Inter_arrival_time_mean.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.005, 0.01, 0.02, 0.03, 0.05, .. , 4)
##      d) Inter-arrival time (stdev): Inter_arrival_time_stdev.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.005, 0.01, 0.15, 0.2, 0.25, .. , 10)
##      e) Throughput                : Tput_whole_trace.threshold<threshold>.<file id>.txt
##                                     Thresholds = (10, 15, 20, 25, 30, 40, 50, 60, .. , 10000)
##      f) Pkt length Entropy        : Pkt_len_entropy.timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 600)
##                                     Thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, .. , 2)
##      g) UDP Connections           : UDP_Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 5, 10, 60, 600)
##                                     Thresholds = (2 .. 30)
##      h) TCP/UDP Connections       : TCP_UDP_Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 5, 10, 60, 600)
##                                     Thresholds = (2 .. 30)
##
## - output:
##      a) How many clients are detected by 1/2/3/4/5... methods
##          ./tethered_clients/summary.<file id>.number_methods.txt
##          format:
##          <number of methods> <number of tethered clients>
##      b) overlapping between methods
##          ./tethered_clients/summary.<file id>.cross_validation.txt
##          format:
##          <method1> <method2> <overlap> <only by former> <only by latter> <# total detected clients> <overlap ratio> <only by former ratio> <only by latter ratio>
##
##  e.g.
##      perl cross_validate_detected_ip.pl 49
##
##################################################


use strict;

use List::Util qw(max min);


#####
## constant
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $FILTERED_SRC_IP = 1;    ## in the trace, some packets are from clients and some are from servers
                            ## we are not interested in those from servers
                            ## it seems the clients from cellular network (Sprint) have IP: 28.XXX.XXX.XXX


#####
## variables
my $input_dir = "./tethered_clients";
my $input_all_client_dir = "./output";
my $output_dir = "./tethered_clients";
my @methods = ("TTL_one_second",
               "TTL_whole_trace",
               "TTL_default_value",
               "TTL_diff",
               "User_agent",
               "Tput_whole_trace.threshold10000",
               "Connections_timebin1.threshold30",
               "Pkt_len_entropy.timebin600.threshold1.2",
               "RTT_variance.threshold0.45",
               "UDP_Connections_timebin1.threshold28",
               "TCP_UDP_Connections_timebin60.threshold14");

my $file_id;

my %tether_info;        ## to store the information of tethered IP
                        ## @{ip}{ip}{detected_methods} - which methods detect this IP as a tethered client
                        ## %{detected_method_number}{detected_method_number} - how many clients are detected by 1/2/3/4/5... methods


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);



#####
## main starts here

my $number_clients = 0;
if($FILTERED_SRC_IP) {
    $number_clients = `cat $input_all_client_dir/file.$file_id.ttl.txt | grep "^28\\\.." | wc -l` + 0;
}
else {
    $number_clients = `cat $input_all_client_dir/file.$file_id.ttl.txt | wc -l` + 0;
}
print "there are $number_clients clients in file $file_id\n" if($DEBUG2);


foreach my $this_method (@methods) {
    my $this_method_file = "$this_method.$file_id.txt";
    print `date` if($DEBUG2);
    print "  $this_method_file\n" if($DEBUG2);


    open FH, "$input_dir/$this_method_file" or die $!;
    while(my $this_ip = <FH>) {
        chomp $this_ip;
        print $this_ip."\n" if($DEBUG1);

        if($FILTERED_SRC_IP == 1) {
            next if(!($this_ip =~ /^28\./));
        }



        push(@{$tether_info{ip}{$this_ip}{detected_methods}}, $this_method);


        #####
        ## DEBUG
        #####
        if($DEBUG0) {
            foreach my $m1 (0 .. scalar(@{$tether_info{ip}{$this_ip}{detected_methods}})-1) {
                foreach my $m2 ($m1+1 .. scalar(@{$tether_info{ip}{$this_ip}{detected_methods}})-1) {
                    if($tether_info{ip}{$this_ip}{detected_methods}[$m1] eq $tether_info{ip}{$this_ip}{detected_methods}[$m2]) {
                        print "$this_ip\n";
                        print "the detected method shouldn't duplicate\n";
                        print "$m1:".$tether_info{ip}{$this_ip}{detected_methods}[$m1]."\n";
                        print "$m2:".$tether_info{ip}{$this_ip}{detected_methods}[$m2]."\n";
                        die "\n";
                    }
                }
            }
        }
    }
    close FH;
}


#####
## Process 
print "\nStart to Process:\n" if($DEBUG2);


#####
## Number of detected methods
foreach my $this_ip (keys %{$tether_info{ip}}) {
    my $num_methods = scalar(@{$tether_info{ip}{$this_ip}{detected_methods}});
    die "# methods shouldn't be 0\n" if($num_methods == 0);

    $tether_info{detected_method_number}{$num_methods} ++;
}

open FH, "> $output_dir/summary.$file_id.number_methods.txt" or die $!;
foreach my $this_num (1 .. scalar(@methods)) {
    if(exists $tether_info{detected_method_number}{$this_num}) {
        print FH "$this_num, ".$tether_info{detected_method_number}{$this_num}.", ".($tether_info{detected_method_number}{$this_num} / $number_clients)."\n";
    }
    else {
        print FH "$this_num, 0, 0\n";
    }
    
}
close FH;



#####
## overlapping with each other
## format:
##   <method1> <method2> <overlap> <only by former> <only by latter> <# total detected clients> <overlap ratio> <only by former ratio> <only by latter ratio>
open FH, "> $output_dir/summary.$file_id.cross_validation.txt" or die $!;
foreach my $ind1 (0 .. scalar(@methods)-1) {
    foreach my $ind2 ($ind1+1 .. scalar(@methods)-1) {
        my $method1 = $methods[$ind1];
        my $method2 = $methods[$ind2];
        print "$method1, $method2\n" if($DEBUG2);
        

        my $cnt_both = 0;       ## number of IPs detected by both methods
        my $cnt_former = 0;     ## number of IPs detected by method1
        my $cnt_latter = 0;     ## number of IPs detected by method2


        foreach my $this_ip (keys %{$tether_info{ip}}) {

            my $detected_methods_str = join(",", (@{$tether_info{ip}{$this_ip}{detected_methods}}));


            if($detected_methods_str =~ /$method1/ and $detected_methods_str =~ /$method2/) {
                ## detected by both methods
                $cnt_both ++;
            }
            elsif($detected_methods_str =~ /$method1/) {
                ## detected by the former method
                $cnt_former ++;
            }
            elsif($detected_methods_str =~ /$method2/) {
                ## detected by the latter method
                $cnt_latter ++;
            }
        }


        print FH "$method1, $method2, $cnt_both, $cnt_former, $cnt_latter, $number_clients, ".($cnt_both / $number_clients).", ".($cnt_former / $number_clients).", ".($cnt_latter / $number_clients)."\n";

    }
}
close FH;