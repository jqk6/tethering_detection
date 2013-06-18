#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/18 @ Narus 
##
## Read in results from "analyze_sprint_text_inter_arrival_time.pl" and detect tethering usage by inter-arrival time.
## e.g. 
##  a) The mean of inter-arrival time is smaller than some threshold
##  b) The stdev of inter-arrival time is larger than some threshold
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_text_inter_arrival_time.pl", i.e.
##     ./output/
##     a) file.<id>.inter_arrival_time.ts.txt
##         timeseries of inter-arrival time of each flow
##
## - output:
##      IP of tethered clients.
##      a) ./tethered_clients/Inter_arrival_time_mean.threshold<threshold>.<file id>.txt
##      b) ./tethered_clients/Inter_arrival_time_stdev.threshold<threshold>.<file id>.txt
##
##  e.g.
##      perl detect_tethering_inter_arrival_time.pl 49
##
##################################################


use strict;

use List::Util qw(max min);
use MyUtil;

#####
## constant
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug



#####
## variables
my $input_dir = "./output";
my $output_dir = "./tethered_clients";

my $file_id;

my %ip_info;        ## to store the information of each IP
                    ## {IP}{ip}{INTERVALS}{intervals}
                    ## {IP}{ip}{INTERVAL_MEAN}{avg of intervals}
                    ## {IP}{ip}{INTERVAL_STDEV}{stdev of intervals}
                    ## {MEAN}{THRESHOLD}{threshold}{TETHERED_IP}{tethered IP}
                    ## {STDEV}{THRESHOLD}{threshold}{TETHERED_IP}{tethered IP}


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);

my $file_intervals = "file.$file_id.inter_arrival_time.ts.txt";


# my @thresholds_mean = (1 .. 20);
# for (0 .. @thresholds_mean-1) {
#     $thresholds_mean[$_] *= 0.05;
# }
my @thresholds_mean = (0.005, 0.01, 0.02, 0.03, 0.05, 0.07, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 3, 4);
# my @thresholds_stdev = (1 .. 50);
# for (0 .. @thresholds_stdev-1) {
#     $thresholds_stdev[$_] *= 0.05;
# }
my @thresholds_stdev = (0.005, 0.01, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5, 5.5, 6, 6.5, 7, 8, 9, 10);


#####
## main starts here

#######################################
## readin IP info:
##
##  inter-arrival time
open FH_ITV, "$input_dir/$file_intervals" or die $!;
while(<FH_ITV>) {
    my ($ip_pair, $num_of_intervals, @intervals) = split(/, /, $_);
    ## convert to numbers
    $num_of_intervals += 0;
    foreach (0 .. @intervals-1) {
        $intervals[$_] += 0;
    }
    @{ $ip_info{IP}{$ip_pair}{INTERVALS}} = @intervals;
    $ip_info{IP}{$ip_pair}{INTERVAL_MEAN} = MyUtil::average(\@intervals);
    $ip_info{IP}{$ip_pair}{INTERVAL_STDEV} = MyUtil::stdev(\@intervals);
    
    print $ip_pair." ($num_of_intervals): ".join(",", @{$ip_info{IP}{$ip_pair}{INTERVALS}})."\n" if($DEBUG1);
    print "  ".$ip_info{IP}{$ip_pair}{INTERVAL_MEAN}.", ".$ip_info{IP}{$ip_pair}{INTERVAL_STDEV}."\n" if($DEBUG1);

}
close FH_ITV;
## end readin IP info
#######################################



#####
## find tethering using inter-arrival time
foreach my $this_ip_pair (keys %{ $ip_info{IP} }) {

    ## method 1: mean
    foreach my $this_threshold (@thresholds_mean) {
        if($ip_info{IP}{$this_ip_pair}{INTERVAL_MEAN} != 0 and 
           $ip_info{IP}{$this_ip_pair}{INTERVAL_MEAN} < $this_threshold) 
        {
            $ip_info{MEAN}{THRESHOLD}{$this_threshold}{TETHERED_IP}{$this_ip_pair} = 1;
        }
    }
    
    ## method 2: stdev
    foreach my $this_threshold (@thresholds_stdev) {
        if($ip_info{IP}{$this_ip_pair}{INTERVAL_STDEV} != 0 and 
           $ip_info{IP}{$this_ip_pair}{INTERVAL_STDEV} > $this_threshold) 
        {
            $ip_info{STDEV}{THRESHOLD}{$this_threshold}{TETHERED_IP}{$this_ip_pair} = 1;
        }
    }

}


#####
## output

#####    
## method 1. mean
foreach my $this_threshold (@thresholds_mean) {
    my $file_output_mean = "Inter_arrival_time_mean.threshold$this_threshold.$file_id.txt";

    open FH, "> $output_dir/$file_output_mean" or die $!;
    foreach my $tethered_ip (keys %{ $ip_info{MEAN}{THRESHOLD}{$this_threshold}{TETHERED_IP} }) {
        print FH "$tethered_ip\n";
    }
    close FH;
}


#####
## method 2. more than one TTL in one second
foreach my $this_threshold (@thresholds_stdev) {
    my $file_output_stdev = "Inter_arrival_time_stdev.threshold$this_threshold.$file_id.txt";

    open FH, "> $output_dir/$file_output_stdev" or die $!;
    foreach my $tethered_ip (keys %{ $ip_info{STDEV}{THRESHOLD}{$this_threshold}{TETHERED_IP} }) {
        print FH "$tethered_ip\n";
    }
    close FH;
}

1;



#####
## functions
