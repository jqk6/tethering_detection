#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/14 @ Narus 
##
## Read in results from "analyze_sprint_text.pl" and detect TTL tethering usage.
## a) > 1 TTL across the whole trace
## b) > 1 TTL at any second
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_text.pl", i.e.
##     ./output/
##     a) file.<id>.ttl.txt
##         TTLs of each flow
##     b) file.<id>.ttl.ts.txt
##         timeseries of # of unique TTLs of each flow
##
## - output:
##      IP of tethered clients.
##      a) ./tethered_clients/TTL_whole_trace.<file id>.txt
##      b) ./tethered_clients/TTL_one_second.<file id>.txt
##
##  e.g.
##      perl detect_tethering_TTL.pl 49
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
                    ## @{ip}{ttls}
                    ## @{ip}{ttl_ts}
                    ## @{tethered_IP_whole_trace}
                    ## @{tethered_IP_one_second}


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);

my $file_ttls   = "file.$file_id.ttl.txt";
my $file_ttl_ts = "file.$file_id.ttl.ts.txt";
my $file_output_whole_trace = "TTL_whole_trace.$file_id.txt";
my $file_output_one_second  = "TTL_one_second.$file_id.txt";


#####
## main starts here

#######################################
## readin IP info:
##
##  ttls
open FH_TTLS, "$input_dir/$file_ttls" or die $!;
while(<FH_TTLS>) {
    my ($ip_pair, $ttl_cnt, @ttls) = split(/, /, $_);

    ## convert to numbers
    $ttl_cnt += 0;
    for (0 .. scalar(@ttls)-1) {
        $ttls[$_] += 0;
    }
    
    ## sanity check
    die "wrong format: $ttl_cnt\n".join(",", @ttls)."\n" if($ttl_cnt != scalar(@ttls));
    

    @{$ip_info{$ip_pair}{ttls}} = @ttls;
}
close FH_TTLS;

##  ttl
open FH_TTL, "$input_dir/$file_ttl_ts" or die $!;
while(<FH_TTL>) {
    my ($ip_pair, @ttl_ts) = split(/, /, $_);
    foreach (0 .. @ttl_ts-1) {
        ## convert to numbers
        $ttl_ts[$_] += 0;
    }
    @{$ip_info{$ip_pair}{ttl_ts}} = @ttl_ts;
    print $ip_pair.": ".join(",", @{$ip_info{$ip_pair}{ttl_ts}})."\n" if($DEBUG1);
}
close FH_TTL;

## end readin IP info
#######################################



#####
## find tethering using TTL
foreach my $this_ip_pair (keys %ip_info) {

    #####    
    ## method 1. more than one TTL across the whole trace
    if(exists($ip_info{$this_ip_pair}{ttls})) {
        if(scalar(@{$ip_info{$this_ip_pair}{ttls}}) > 1) {
            $ip_info{tethered_IP_whole_trace}{$this_ip_pair} = 1;
        }
    }


    #####
    ## method 2. more than one TTL in one second
    foreach my $ind (0 ... scalar(@{$ip_info{$this_ip_pair}{ttl_ts}})-1) {
        my $this_ttl = $ip_info{$this_ip_pair}{ttl_ts}[$ind];

        if($this_ttl > 1) {
            ## tethering detected!!
            $ip_info{tethered_IP_one_second}{$this_ip_pair} = 1;
            last;
        }
    }

}


#####
## output

#####    
## method 1. more than one TTL across the whole trace
open FH, "> $output_dir/$file_output_whole_trace" or die $!;
foreach my $tethered_ip (keys %{$ip_info{tethered_IP_whole_trace}}) {
    print FH "$tethered_ip\n";
}
close FH;

#####
## method 2. more than one TTL in one second
open FH, "> $output_dir/$file_output_one_second" or die $!;
foreach my $tethered_ip (keys %{$ip_info{tethered_IP_one_second}}) {
    print FH "$tethered_ip\n";
}
close FH;

1;



#####
## functions
