#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/18 @ Narus 
##
## Read in results from "analyze_sprint_text.pl" and detect tethering usage by throughput.
## e.g. The tput is larger than some threshold
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_text.pl", i.e.
##     ./output/
##     file.<id>.tput.ts.txt
##         timeseries of tput of each flow
##
## - output:
##      IP of tethered clients.
##      ./tethered_clients/Tput_whole_trace.threshold<threshold>.<file id>.txt
##
##  e.g.
##      perl detect_tethering_tput.pl 49
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
                    ## {IP}{ip}{TPUT_TS}{tput timeseries}
                    ## {IP}{ip}{TPUT_MEAN}{avg of tput}
                    ## {THRESHOLD}{threshold}{TETHERED_IP}{tethered IP}


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);

my $file_tput_ts = "file.$file_id.tput.ts.txt";


my @thresholds = (10, 15, 20, 25, 30, 40, 50, 60, 70, 80, 90, 100, 120, 140, 160, 180, 200, 250, 300, 400, 500, 600, 700, 800, 900, 1000, 1500, 2000, 3000, 5000, 10000);


#####
## main starts here

#######################################
## readin IP info:
##
##  tput
open FH_TPUT, "$input_dir/$file_tput_ts" or die $!;
while(<FH_TPUT>) {
    ## collect total info

    my ($ip_pair, @tput_ts) = split(/, /, $_);
    foreach (0 .. @tput_ts-1) {
        ## convert to numbers
        $tput_ts[$_] += 0;
    }
    
    @{ $ip_info{IP}{$ip_pair}{TPUT_TS} } = @tput_ts;
    $ip_info{IP}{$ip_pair}{TPUT_MEAN} = MyUtil::average(\@tput_ts);

    print $ip_pair.": ".join(",", @{ $ip_info{IP}{$ip_pair}{TPUT_TS} })."\n" if($DEBUG1);
    print "  ".$ip_info{IP}{$ip_pair}{TPUT_MEAN}."\n" if($DEBUG1);
}
close FH_TPUT;
## end readin IP info
#######################################



#####
## find tethering using inter-arrival time
foreach my $this_ip_pair (keys %{ $ip_info{IP} }) {

    foreach my $this_threshold (@thresholds) {
        if($ip_info{IP}{$this_ip_pair}{TPUT_MEAN} > $this_threshold) 
        {
            $ip_info{THRESHOLD}{$this_threshold}{TETHERED_IP}{$this_ip_pair} = 1;
        }
    }

}


#####
## output

#####    
## method 1. mean
foreach my $this_threshold (@thresholds) {
    my $file_output = "Tput_whole_trace.threshold$this_threshold.$file_id.txt";

    open FH, "> $output_dir/$file_output" or die $!;
    foreach my $tethered_ip (keys %{ $ip_info{THRESHOLD}{$this_threshold}{TETHERED_IP} }) {
        print FH "$tethered_ip\n";
    }
    close FH;
}


1;



#####
## functions
