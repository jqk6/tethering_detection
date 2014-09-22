#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2014.04.14 @ UT Austin
##
## - input:
##   1. ip: the ip that collected the trace (the target client device)
##
## - output:
##
## - e.g.
##   perl tshark_cmd.sigcomm04.pl
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
my $input_dir  = "/scratch/cluster/yichao/tethering_detection/data/sigcomm2004";
my $output_dir = "../processed_data/subtask_parse_sigcomm04/tshark";
my $output_file;

# my $monitor;
my $filename;

#############
# check input
#############
if(scalar(@ARGV) != 0) {
    print "wrong number of input: ".@ARGV."\n";
    print join("\n", @ARGV)."\n";
    exit;
}
# $monitor = $ARGV[0];
# $output_file .= ".$monitor";

if($DEBUG2) {
    print "input:\n";
    print "  input dir: $input_dir\n";
}


#############
# Main starts
#############

## read all files
print "read all files\n" if($DEBUG2);
my @files;
opendir(my $dh, $input_dir) or die $!;
while(readdir $dh) {
    next if(-d "$input_dir/$_");

    print "  $input_dir/$_\n" if($DEBUG0);
    push @files, $_;
}
closedir $dh;
# my @files = ("chihuahuan-ath0");
# my @files = ("chihuahuan-ath1");
# my @files = ("chihuahuan-ath2-00");
# my @files = ("chihuahuan-ath2-01");
# my @files = ("chihuahuan-ath2-02");
# my @files = ("chihuahuan-ath2-03");
# my @files = ("chihuahuan-ath2-04");


## sort files by name
print "sort files by name\n" if($DEBUG2);
# foreach my $cfilename (sort {$a <=> $b} (@files)) {
foreach my $cfilename (@files) {

    my $filename;
    if($cfilename =~ /(chihuahuan-ath.*)\.gz/) {
        $filename = $1;

        ## decompress
        next;
        print "  decompress pcap file\n" if($DEBUG2);
        my $cmd = "gunzip \"$input_dir/$filename.gz\"";
        `$cmd`;
    }
    elsif($cfilename =~ /(chihuahuan-ath.*)/) {
        $filename = $1;
    }
    else {
        next;
    }
    print "  $filename:\n" if($DEBUG2);
    # next;
    
    ## clear output file
    $output_file = $filename;
    if(-e "$output_dir/$output_file.txt") {
        my $cmd = "rm \"$output_dir/$output_file.txt\"";
        `$cmd`;
    }
    if(-e "$output_dir/$output_file.txt.bz2") {
        my $cmd = "rm \"$output_dir/$output_file.txt.bz2\"";
        `$cmd`;
    }


    ## tshark 
    print "  run tshark\n" if($DEBUG2);
    my $cmd = "tshark -r \"$input_dir/$filename\" -R \"ip.ttl == 64 || ip.ttl == 128\" -T fields -E separator=\\\| -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.id -e ip.ttl -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -e tcp.window_size_scalefactor -e tcp.option_kind -e http.user_agent -e tcp.analysis.bytes_in_flight > \"$output_dir/$output_file.txt\"";

    print "    > ".$cmd."\n";
    `$cmd`;


    ## compress pcap file
    print "  compress pcap file\n" if($DEBUG2);
    $cmd = "gzip \"$input_dir/$filename\"";
    `$cmd`;

    ## compress output file
    print "compress output file\n" if($DEBUG2);
    my $cmd = "bzip2 \"$output_dir/$output_file.txt\"";
    `$cmd`;


}




1;
