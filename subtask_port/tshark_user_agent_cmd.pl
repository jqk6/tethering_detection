#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## - input:
##   1. ip: the ip that collected the trace (the target client device)
##   2. trace_fullpath: pcap full path
##
## - output:
##
## - e.g.
##
##########################################

use strict;
use lib "../utils";

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print output


#############
# Constants
#############


#############
# Variables
#############
my $input_dir  = "";
my $output_dir = "../processed_data/subtask_port/text";

my $ip;
my $trace_fullpath;
my $filename;

#############
# check input
#############
if(@ARGV != 2) {
    print "wrong number of input: ".@ARGV."\n";
    print join("\n", @ARGV)."\n";
    exit;
}
$ip = $ARGV[0];
$trace_fullpath = $ARGV[1];
if($trace_fullpath =~ /(.*)\/(.*)$/) {
    $input_dir = $1;
    $filename = $2;
}

if($DEBUG2) {
    print "device ip: $ip\n";
    print "input dir: $input_dir\n";
    print "trace file: $filename\n";
}


#############
# Main starts
#############
my $cmd = "tshark -r $trace_fullpath -R \"ip.addr == $ip\" -T fields -E separator=\\\| -e ip.src -e http.user_agent > $output_dir/$filename.ua.txt";

print $cmd."\n";
`$cmd`;


## sort
$cmd = "cat $output_dir/$filename.ua.txt | sort | uniq > $output_dir/$filename.ua.uniq.txt";
`$cmd`;

$cmd = "mv $output_dir/$filename.ua.uniq.txt $output_dir/$filename.ua.txt";
`$cmd`;

## compress
$cmd = "bzip2 $output_dir/$filename.ua.uniq.txt $output_dir/$filename.ua.txt";
`$cmd`;


