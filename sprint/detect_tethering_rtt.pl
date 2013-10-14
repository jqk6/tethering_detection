#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/18 @ Narus 
##
## Read in results from "analyze_sprint_tcp_rtt.pl" and detect tethering using the variance of RTT.
## e.g. when variance of RTT to the same destination is larger than some threshold
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_tcp_rtt.pl", i.e.
##     ./output/
##     file.<id>.rtts.txt: 
##      the RTT to different destinations
##      format:
##          <src ip>, <dst ip>, <RTTs>
##
## - output:
##      IP of tethered clients.
##          ./tethered_clients/RTT_variance.threshold<threshold>.<file id>.txt
##
##  e.g.
##      perl detect_tethering_rtt.pl 49
##
##################################################


use strict;

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
                    ## {SRC}{src}{DST}{dst}{RTT}{rtts}
                    ## {IP}{ip}{RTT_MEAN}{rtt means}    - RTT mean of each destination
                    ## {IP}{ip}{RTT_VAR}{rtt means}     - RTT variance of each destination
                    ## {THRESHOLD}{threshold}{TETHERED_IP}{tethered ips}
my @thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8);

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

#######################################
## readin IP info:
##
##  RTTs
my $file_name = "file.$file_id.rtts.txt";
open FH, "$input_dir/$file_name" or die $!."\n$file_name\n";
while(<FH>) {
    my ($src, $dst, @rtts) = split(/, /, $_);
    ## convert to numbers
    for (0 .. @rtts-1) {
        $rtts[$_] += 0;
    }

    print "$src > $dst has ".join(",", @rtts)."\n" if($DEBUG1);

    
    @{ $ip_info{SRC}{$src}{DST}{$dst}{RTT} } = @rtts;
}
close FH;    
## end readin IP info
#######################################


#####
## find tethering using # of connections
foreach my $this_src (keys %{ $ip_info{SRC} }) {
    foreach my $this_dst (keys %{ $ip_info{SRC}{$this_src}{DST} }) {
        my $rtt_mean  = MyUtil::average(\@{ $ip_info{SRC}{$this_src}{DST}{$this_dst}{RTT} });
        my $rtt_stdev = MyUtil::stdev  (\@{ $ip_info{SRC}{$this_src}{DST}{$this_dst}{RTT} });


        print "$this_src > $this_dst: ".join(",", @{ $ip_info{SRC}{$this_src}{DST}{$this_dst}{RTT} })."\n" if($DEBUG1); 
        print "             mean=$rtt_mean, stdev=$rtt_stdev\n" if($DEBUG1);


        foreach my $this_threshold (@thresholds) {
            if($rtt_stdev > $this_threshold) {
                $ip_info{THRESHOLD}{$this_threshold}{TETHERED_IP}{$this_src} = 1;
            }
        }

    }
}


#####
## output
foreach my $this_threshold (@thresholds) {
    my $file_output = "RTT_variance.threshold$this_threshold.$file_id.txt";
    open FH, "> $output_dir/$file_output" or die $!;
    foreach my $this_ip (keys %{ $ip_info{THRESHOLD}{$this_threshold}{TETHERED_IP} }) {
        print FH $this_ip."\n";
    }
    close FH;
}


1;



#####
## functions
