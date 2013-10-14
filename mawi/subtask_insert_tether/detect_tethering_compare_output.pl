#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## detect_tethering.pl outputs a list the detected tethering IPs and this codes take this output and ground truth (ip mapping) to see if these heuristics detect all the tethered IPs. The only problem is, because even the original trace can have tethering, we want to remove these IPs to prevent the false positive. Therefore the code take the third input which is the tethering detection results from the original trace.
##
##
## - input: 
##   1. ip_map_file
##     format
##     <from ip>, <to ip>
##   2. w_insert_file
##     format
##     <tethering ip>
##   3. wo_insert_file (option)
##     format
##     <tethering ip>
##    
##
## - detect_tethering_compare_output.pl <ip_map_file> <w_insert_file> <wo_insert_file>
##      e.g.
##      perl detect_tethering_compare_output.pl exp0.txt 201101091400.dump.txt.exp0.txt 201101091400.dump.txt
##
##########################################

use lib "../../utils";

use strict;
use Tethering;
use MyUtil;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 0;     ## program flow
my $DEBUG3 = 1;     ## results


#############
# Constants
#############
my $FIX_DST      = 0; ## 1 to fix the TCP destination
my $FIX_DST_ADDR = "192.168.5.67";
my $FIX_SRC      = 0; ## 1 to fix the TCP src
my $FIX_SRC_ADDR = "^28\.";

my $MIN_NUM_PKTS = 0;


#############
# Variables
#############
my $input_ip_map_dir    = "../../processed_data/mawi/ip_mapping";
my $input_tether_ip_dir = "../../processed_data/mawi/subtask_tethering_detection/tether_ips";
my $output_dir          = "../../processed_data/mawi/subtask_tethering_detection/tether_ips_compare";

my $ip_map_file;
my $w_insert_file;
my $wo_insert_file = -1;

my %ip_mapping = ();
my %tethered_ips = ();
my %non_tethered_ips = ();
my %discard_ips = ();
my %results = ();


#############
# check input
#############
if(@ARGV != 2 and @ARGV != 3) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$ip_map_file = $ARGV[0];
$w_insert_file = $ARGV[1];
if(@ARGV == 3) {
    $wo_insert_file = $ARGV[2];
}
print "ip mapping: $input_ip_map_dir/$ip_map_file\n" if($DEBUG2);
print "results w/  insertion: $input_tether_ip_dir/$w_insert_file\n" if($DEBUG2);
print "results w/o insertion: $input_tether_ip_dir/$wo_insert_file\n" if($DEBUG2);


#############
# Main starts
#############

#############
## Read the IP mapping
#############
print "Read the IP mapping\n" if($DEBUG2);
open FH, "$input_ip_map_dir/$ip_map_file" or die $!;
while(<FH>) {
    my ($from_ip, $to_ip) = split(/, |\n/, $_);
    print "'$from_ip', '$to_ip'\n" if($DEBUG0);

    $ip_mapping{$to_ip} = $from_ip;
}
close FH;


#############
## Read the tethering results from "w/ tethering insertion trace"
#############
opendir(DIR, $input_tether_ip_dir) or die $!;
while (my $file = readdir(DIR)) {
    next if($file =~ /^\.+/);  ## don't show "." and ".."
    next if(-d "$input_tether_ip_dir/$file");  ## don't show directories
    next if($file =~ /nontether.txt$/);
    
    if($file =~ /^$w_insert_file\.(.*)\.txt$/) {
        my $heuristic = $1;

        print "$file\n" if($DEBUG0);
        print "  heuristic: $heuristic\n" if($DEBUG2);

        open FH, "$input_tether_ip_dir/$file" or die $!;
        while(<FH>) {
            chomp;
            my $this_ip = $_;
            print "    '$this_ip'\n" if($DEBUG0);
            $tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        close FH;
    }
}
closedir(DIR);


#############
## Read the non-tethering results from "w/ tethering insertion trace"
#############
print "Read the non-tethering results from \"w/ tethering insertion trace\"\n" if($DEBUG2);
foreach my $heuristic (keys %{ $tethered_ips{HEURISTIC} }) {
    print "  $input_tether_ip_dir/$w_insert_file.$heuristic.nontether.txt\n" if($DEBUG0);

    open FH, "$input_tether_ip_dir/$w_insert_file.$heuristic.nontether.txt" 
            or die $!."$input_tether_ip_dir/$w_insert_file.$heuristic.nontether.txt";
    while(<FH>) {
        chomp;
        my $this_ip = $_;
        print "    '$this_ip'\n" if($DEBUG0);
        $non_tethered_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
    }
    close FH;

}

#############
## Read the tethering results from "w/o tethering insertion trace"
#############
if($wo_insert_file != -1) {
    print "Read the tethering results from \"w/o tethering insertion trace\"\n" if($DEBUG2);
    foreach my $heuristic (keys %{ $tethered_ips{HEURISTIC} }) {
        print "  $input_tether_ip_dir/$wo_insert_file.$heuristic.txt\n" if($DEBUG0);

        open FH, "$input_tether_ip_dir/$wo_insert_file.$heuristic.txt" 
            or die $!."$input_tether_ip_dir/$wo_insert_file.$heuristic.txt";
        while(<FH>) {
            chomp;
            my $this_ip = $_;
            print "    '$this_ip'\n" if($DEBUG0);
            $discard_ips{HEURISTIC}{$heuristic}{IP}{$this_ip} = 1;
        }
        close FH;
    }
}


#############
## Evaluate the results
#############
print "Evaluate the results\n" if($DEBUG2);
foreach my $heuristic (keys %{ $tethered_ips{HEURISTIC} }) {
    print "  $heuristic\n" if($DEBUG2);

    $results{HEURISTIC}{$heuristic}{TP} = 0;
    $results{HEURISTIC}{$heuristic}{TN} = 0;
    $results{HEURISTIC}{$heuristic}{FP} = 0;
    $results{HEURISTIC}{$heuristic}{FN} = 0;

    ## for each detected IPs
    foreach my $this_ip (keys %{ $tethered_ips{HEURISTIC}{$heuristic}{IP} }) {
        ## also detected in "w/o tether insertion trace", so just discard this IP
        next if($wo_insert_file != -1 and exists $discard_ips{HEURISTIC}{$heuristic}{IP}{$this_ip});

        ## if it's ground truth -- TP
        if(exists $ip_mapping{$this_ip}) {
            $results{HEURISTIC}{$heuristic}{TP} ++;
        }
        ## if it's not in ground truth -- FP
        else {
            $results{HEURISTIC}{$heuristic}{FP} ++;
        }
    }

    ## for each IP which is not detected as tethering by the heuristic
    foreach my $this_ip (keys %{ $non_tethered_ips{HEURISTIC}{$heuristic}{IP} }) {
        ## if it's ground truth -- FN
        if(exists $ip_mapping{$this_ip}) {
            $results{HEURISTIC}{$heuristic}{FN} ++;
        }
        ## if it's not in ground truth -- TN
        else {
            $results{HEURISTIC}{$heuristic}{TN} ++;
        }
    }
}


#############
## Output the results
#############
print "Output the results\n" if($DEBUG2);
print "  [TP, TN, FP, FN, precision, recall, f1_score]\n";
foreach my $heuristic (keys %{ $tethered_ips{HEURISTIC} }) {
    print "  $heuristic\n" if($DEBUG2 or $DEBUG3);

    my $tp = $results{HEURISTIC}{$heuristic}{TP};
    my $tn = $results{HEURISTIC}{$heuristic}{TN};
    my $fp = $results{HEURISTIC}{$heuristic}{FP};
    my $fn = $results{HEURISTIC}{$heuristic}{FN};
    my $precision = MyUtil::precision($tp, $fn, $fp, $tn);
    my $recall = MyUtil::recall($tp, $fn, $fp, $tn);
    my $f1_score = MyUtil::f1_score($tp, $fn, $fp, $tn);

    my $discard = 0;
    $discard = 1 if($wo_insert_file != -1);
    open FH, ">$output_dir/$w_insert_file.$heuristic.discard$discard.txt" or die $!;
    print FH "$tp, $tn, $fp, $fn, $precision, $recall, $f1_score\n";
    print "    $tp, $tn, $fp, $fn, $precision, $recall, $f1_score\n" if($DEBUG3);
    close FH;
}



