#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.12.14 @ UT Austin
##
## - input:
##
## - output:
##
## - e.g.
##   perl merge_pcap.pl
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
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
my $input_dir  = "/u/yichao/anomaly_compression/data/sjtu_wifi/pcap";
my $output_dir = "/u/yichao/anomaly_compression/data/sjtu_wifi/pcap";


#############
# check input
#############
if(@ARGV != 0) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
# $ARGV[0];


#############
# Main starts
#############

my $cmd = "mergecap -w $output_dir/merge.pcap ";
opendir(my $dh, $input_dir) || die;
while(readdir $dh) {
    next if($_ =~ /^\./);
    print "$input_dir/$_\n";

    my $escape_file = "$input_dir/$_";
    $escape_file =~ s/ /\\ /g;
    $cmd .= "$escape_file ";
}
closedir $dh;

print $cmd."\n";
`$cmd`;

