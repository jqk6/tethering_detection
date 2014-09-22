#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## - input:
##
## - output:
##
## - e.g.
##   perl analyze_os.pl 111.18 sjtu_wifi_merge.pcap.ua.txt.bz2
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
my $DEBUG4 = 0; ## print unknown UA
my $DEBUG5 = 0; ## 
my $DEBUG6 = 0; ## 

#############
# Constants
#############
my $TOP_N = 10;

#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_port/text";
my $output_dir = "../processed_data/subtask_port/analysis";
my $figure_dir = "../processed_data/subtask_port/analysis_figures";

my $gnuplot_port = "plot_port";
my $gnuplot_dist = "plot_dist";

my $ip;
my $filename;

my %ip_info = ();  ## IP - OS
my %os_info = ();

my @OS_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "HTC", "Samsung", "SPH-M910", "VM670", "LGE", "Darwin", "iOS");
my @OSs         = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux", "Android", "Android", "Android", "Android", "Android", "Apple", "Apple");
my @device_keywords = ("HTC", "Samsung", "SPH-M910", "VM670", "LGE", "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox", "Wii");
my @devices         = ("HTC", "Samsung", "Samsung",  "LG",    "LG",  "NOKIA", "Windows Phone", "iPad", "iPhone", "MacBookAir", "Xbox", "Wii");



#############
# check input
#############
if(@ARGV != 2) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$ip       = $ARGV[0];
$filename = $ARGV[1];
if($DEBUG2) {
    print "ip: $ip\n";
    print "file: $filename\n";
}


#############
# Main starts
#############

#############
# read trace file
#############
print "start to read trace file\n" if($DEBUG2);

# open FH, "$input_dir/$filename" or die $!;
open FH, "bzcat $input_dir/$filename |" or die $!;
while(<FH>) {
    chomp;
    print "> $_\n" if($DEBUG5);

    my ($ip_src, $user_agent) = split(/\|/, $_);
    print "  $ip_src: '$user_agent'\n" if($DEBUG5);

    my @tmp_ips = split(/,/, $ip_src);
    foreach my $this_ip (@tmp_ips) {
        next unless($this_ip =~ /$ip/);
        next if($user_agent eq "");

        ## OS
        my $find_os = 0;
        foreach my $i (0 .. @OS_keywords-1) {
            my $this_key = $OS_keywords[$i];
            my $this_os  = $OSs[$i];

            if($user_agent =~ /$this_key/i) {
                $ip_info{$this_ip}{OS}{$this_os} = 1;
                $os_info{OS}{$this_os}{$this_ip} = 1;
                $find_os ++;
            }
        }

        ## Device
        my $find_device = 0;
        foreach my $i (0 .. @device_keywords-1) {
            my $this_key    = $device_keywords[$i];
            my $this_device = $devices[$i];

            if($user_agent =~ /$this_key/i) {
                $ip_info{$this_ip}{DEVICE}{$this_device} = 1;
                $os_info{DEVICE}{$this_device}{$this_ip} = 1;
                $find_device ++;
            }
        }

        ## print unknown user agents
        if($DEBUG4 and ($find_os == 0 or $find_os > 1) and ($find_device == 0 or $find_device > 1) ) {
            print "  unknown: '$user_agent'\n";
        }
    }
}
close FH;


print "  num ips: ".scalar(keys (%ip_info))."\n";
print "  OS:\n";
foreach my $this_os (keys %{ $os_info{OS} }) {
    print "    $this_os: ".scalar(keys %{ $os_info{OS}{$this_os} })."\n";
}
print "  Device:\n";
foreach my $this_device (keys %{ $os_info{DEVICE} }) {
    print "    $this_device: ".scalar(keys %{ $os_info{DEVICE}{$this_device} })."\n";
}
print "\n";


#############
## output os
#############
print "output os\n" if($DEBUG2);

$os_info{OS}     = ();
$os_info{DEVICE} = ();
# my $stat_num_ip  = 0;

open FH, ">$output_dir/$filename.os.txt" or die $!;
open FH_DEV, ">$output_dir/$filename.device.txt" or die $!;
foreach my $this_ip (keys %ip_info) {
    if(scalar(keys %{ $ip_info{$this_ip}{OS} }) == 1) {
        foreach my $this_os (keys %{ $ip_info{$this_ip}{OS} }) {
            print FH "$this_ip, $this_os\n";
            $os_info{OS}{$this_os}{$this_ip} = 1;
        }
    }
    if(scalar(keys %{ $ip_info{$this_ip}{DEVICE} }) == 1) {
        foreach my $this_device (keys %{ $ip_info{$this_ip}{DEVICE} }) {
            print FH_DEV "$this_ip, $this_device\n";
            $os_info{DEVICE}{$this_device}{$this_ip} = 1;
        }
    }
}
close FH;
close FH_DEV;

print "  OS:\n";
foreach my $this_os (keys %{ $os_info{OS} }) {
    print "    $this_os: ".scalar(keys %{ $os_info{OS}{$this_os} })."\n";
}
print "  Device:\n";
foreach my $this_device (keys %{ $os_info{DEVICE} }) {
    print "    $this_device: ".scalar(keys %{ $os_info{DEVICE}{$this_device} })."\n";
}
print "\n";
