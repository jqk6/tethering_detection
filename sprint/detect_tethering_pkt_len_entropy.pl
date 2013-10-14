#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/18 @ Narus 
##
## Read in results from "analyze_sprint_text.pl" and detect tethering usage by entropy of pkt length.
## e.g. The entropy is larger than some threshold
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_text.pl", i.e.
##     ./output/
##     file.<file id>.len_entropy.ts.txt
##         timeseries of packet len entropy of each flow
##
## - output:
##      IP of tethered clients.
##      ./tethered_clients/Pkt_len_entropy.timebin<time bin size>.threshold<threshold>.<file id>.txt
##
##  e.g.
##      perl detect_tethering_pkt_len_entropy.pl 49
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
                    ## {IP}{ip}{ENTROPY_TS}{tput timeseries}
                    ## {IP}{ip}{ENTROPY_MEAN}{avg of entropy}
                    ## {TIME_BIN_SIZE}{time bin size}{THRESHOLD}{threshold}{TETHERED_IP}{tethered IP}


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);

my $file_len_entropy_ts = "file.$file_id.len_entropy.ts.txt";


my @timebins = (1, 600);
my @thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, 0.035, 0.04, 0.045, 0.05, 0.055, 0.06, 0.07, 0.08, 0.09, 0.1, 0.15, 0.2, 0.25, 0.3, 0.5, 0.7, 0.9, 1, 1.2, 1.4, 1.6, 1.8, 2);


#####
## main starts here

#######################################
## readin IP info:
##
##  entropy
open FH_ENT, "$input_dir/$file_len_entropy_ts" or die $!;
while(<FH_ENT>) {
    my ($ip_pair, @entropy_ts) = split(/, /, $_);
    foreach (0 .. @entropy_ts-1) {
        ## convert to numbers
        $entropy_ts[$_] += 0;
    }
    @{ $ip_info{IP}{$ip_pair}{ENTROPY_TS} } = @entropy_ts;
    $ip_info{IP}{$ip_pair}{ENTROPY_MEAN} = MyUtil::average(\@entropy_ts);

    print $ip_pair.": ".join(",", @{ $ip_info{IP}{$ip_pair}{ENTROPY_TS}})."\n" if($DEBUG1);
    print "  ".$ip_info{IP}{$ip_pair}{ENTROPY_MEAN}."\n" if($DEBUG1);
}
close FH_ENT;
## end readin IP info
#######################################



#####
## find tethering using inter-arrival time
foreach my $this_timebin (@timebins) {
    foreach my $this_ip_pair (keys %{ $ip_info{IP} }) {
        foreach my $this_threshold (@thresholds) {

            if($this_timebin == 1) {
                foreach my $this_ent (@{ $ip_info{IP}{$this_ip_pair}{ENTROPY_TS} }) {
                    if($this_ent > $this_threshold) {
                        $ip_info{TIME_BIN_SIZE}{$this_timebin}{THRESHOLD}{$this_threshold}{TETHERED_IP}{$this_ip_pair} = 1;
                        last;
                    }
                }
            }
            else {
                if($ip_info{IP}{$this_ip_pair}{ENTROPY_MEAN} > $this_threshold) 
                {
                    $ip_info{TIME_BIN_SIZE}{$this_timebin}{THRESHOLD}{$this_threshold}{TETHERED_IP}{$this_ip_pair} = 1;
                }    
            }

        }
    }
}


#####
## output

foreach my $this_timebin (@timebins) {
    foreach my $this_threshold (@thresholds) {
        my $file_output = "Pkt_len_entropy.timebin$this_timebin.threshold$this_threshold.$file_id.txt";

        open FH, "> $output_dir/$file_output" or die $!;
        foreach my $tethered_ip (keys %{ $ip_info{TIME_BIN_SIZE}{$this_timebin}{THRESHOLD}{$this_threshold}{TETHERED_IP} }) {
            print FH "$tethered_ip\n";
        }
        close FH;
    }
}

1;



#####
## functions
