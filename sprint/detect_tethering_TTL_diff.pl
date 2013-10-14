#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/27 @ Narus 
##
## Read in results from "analyze_sprint_text.pl" and detect TTL tethering usage.
## if there are multiple TTLs and their difference is 1 (or < some small number)
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_text.pl", i.e.
##     ./output/
##     file.<id>.ttl.txt
##         TTLs of each flow
##
## - output:
##      IP of tethered clients.
##      ./tethered_clients/TTL_diff.<file id>.txt
##
##  e.g.
##      perl detect_tethering_TTL_diff.pl 49
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
my $threshold = 2;

my $file_id;

my %ip_info;        ## to store the information of each IP
                    ## {IP}{ip}{TTLS}{ttls}
                    ## {TETHERED_IP}{tethered IP}
                    

#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);

my $file_ttls   = "file.$file_id.ttl.txt";
my $file_output = "TTL_diff.$file_id.txt";


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
    

    @{ $ip_info{IP}{$ip_pair}{TTLS} } = @ttls;
}
close FH_TTLS;
## end readin IP info
#######################################



#####
## find tethering using TTL
foreach my $this_ip_pair (keys %{ $ip_info{IP} }) {

    foreach my $ind_1 (0 .. @{ $ip_info{IP}{$this_ip_pair}{TTLS} }-1) {
        foreach my $ind_2 ($ind_1+1 .. @{ $ip_info{IP}{$this_ip_pair}{TTLS} }-1) {
            my $this_ttl_1 = $ip_info{IP}{$this_ip_pair}{TTLS}[$ind_1];
            my $this_ttl_2 = $ip_info{IP}{$this_ip_pair}{TTLS}[$ind_2];

            die "duplicate TTL value in one client: $this_ip_pair\n" if($this_ttl_1 == $this_ttl_2);

            if(abs($this_ttl_1 - $this_ttl_2) < $threshold) {
                $ip_info{TETHERED_IP}{$this_ip_pair} = 1;
            } 
        }
    }

}


#####
## output
open FH, "> $output_dir/$file_output" or die $!;
foreach my $tethered_ip (keys %{ $ip_info{TETHERED_IP} }) {
    print FH "$tethered_ip\n";
}
close FH;


1;



#####
## functions
