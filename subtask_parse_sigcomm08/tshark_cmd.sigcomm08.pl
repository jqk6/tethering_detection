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
##   perl tshark_cmd.sigcomm08.pl 4
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
my $input_dir  = "/scratch/cluster/yichao/tethering_detection/data/sigcomm2008";
# my $input_dir  = "/scratch/cluster/yichao/tethering_detection/data/umass_cellular/pcap/belch";
my $output_dir = "../processed_data/subtask_parse_sigcomm08/tshark";
my $output_file = "sigcomm08";

my $monitor;

my $filename;
my $dhcp_ip1 = "26.12.0.0/16";
my $dhcp_ip2 = "26.2.0.0/16";

#############
# check input
#############
if(scalar(@ARGV) != 1) {
    print "wrong number of input: ".@ARGV."\n";
    print join("\n", @ARGV)."\n";
    exit;
}
$monitor = $ARGV[0];
$output_file .= ".$monitor";

if($DEBUG2) {
    print "input:\n";
    print "  device ip: $dhcp_ip1, $dhcp_ip2\n";
    print "  input dir: $input_dir\n";
    print "  trace file: $filename\n";
}


#############
# Main starts
#############


## clear output file
if(-e "$output_dir/$output_file.txt") {
    my $cmd = "rm \"$output_dir/$output_file.txt\"";
    `$cmd`;
}
if(-e "$output_dir/$output_file.txt.bz2") {
    my $cmd = "rm \"$output_dir/$output_file.txt.bz2\"";
    `$cmd`;
}



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


## sort files by name
print "sort files by name\n" if($DEBUG2);
# foreach my $cfilename (sort {$a <=> $b} (@files)) {
foreach my $cfilename (sort {file_time($a) <=> file_time($b)} (@files)) {
    my $filename;
    if($cfilename =~ /(sigcomm08\_wl\_$monitor\_2008.*)\.pcap\.gz/) {
        $filename = $1;
    }
    else {
        next;
    }
    print "  $filename:\n" if($DEBUG2);

    ## decompress
    print "  decompress pcap file\n" if($DEBUG2);
    my $cmd = "gunzip \"$input_dir/$filename.pcap.gz\"";
    `$cmd`;


    ## tshark 
    print "  run tshark\n" if($DEBUG2);
    my $cmd = "tshark -r \"$input_dir/$filename.pcap\" -R \"ip.src == $dhcp_ip1 || ip.src == $dhcp_ip2\" -T fields -E separator=\\\| -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.id -e ip.ttl -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -e tcp.window_size_scalefactor -e tcp.option_kind -e http.user_agent -e tcp.analysis.bytes_in_flight >> \"$output_dir/$output_file.txt\"";

    print "    > ".$cmd."\n";
    `$cmd`;


    ## compress pcap file
    print "  compress pcap file\n" if($DEBUG2);
    $cmd = "gzip \"$input_dir/$filename.pcap\"";
    `$cmd`;

}


## compress output file
print "compress output file\n" if($DEBUG2);
my $cmd = "bzip2 \"$output_dir/$output_file.txt\"";
`$cmd`;


1;

sub file_time {
    my ($filename) = @_;

    if($filename =~ /sigcomm08\_wl\_\d\_2008-08-(\d+)\_(\d+)-(\d+)_(\d+)/) {
        return ($1*24*60*60 + $2*60*60 + $3*60 + $4);
    }
    else {
        return -1;
    }
}
