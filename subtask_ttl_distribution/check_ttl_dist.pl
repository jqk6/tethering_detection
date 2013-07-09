#!/bin/perl 

########################################
## Author: Yi-Chao Chen 
## 2013/06/19 @ Narus 
##
## a) Check the distribution of TTL values.
## b) Check if the TTLs behind a mobile station only differs by 1.
##
## - input: ../output/file.$file_id.ttl.txt
##
## - output:
##      ./output/
##      a) ttl_all_dist.txt
##         ttl_normal_dist.txt
##         ttl_tether_dist.txt
##          <TTL> <count>
##      b) ttl_diff.txt
##          <TTL diff> <count>
##  e.g.
##      perl check_ttl_dist.pl
##
########################################

use strict;

use List::Util qw(max min);

#####
## variables
my $input_dir = "../output";
my $output_dir = "./output";
my $file_all_dist = "ttl_all_dist.txt";
my $file_normal_dist = "ttl_normal_dist.txt";
my $file_tether_dist = "ttl_tether_dist.txt";
my $file_diff = "ttl_diff.txt";

my %ttl_info;       ## to store information about ttl
                    ## {TTL}{ttl value}{CNT}{cnt}
                    ## {NORMAL_TTL}{ttl value}{CNT}{cnt} 
                    ## {TETHER_TTL}{ttl value}{CNT}{cnt} 
                    ## {TTL_DIFF}{ttl value}{CNT}{cnt} 

#####
## main starts here
foreach my $file_id (49 .. 199, 0 .. 48) {
# foreach my $file_id (49) {
    my $cnt_clients = 0;
    my %cnt_ttls;           ## cnt_ttls{tether_client}{ttl value}
                            ## cnt_ttls{normal_client}{ttl value}


    #####
    ## get file name
    my $file = "$input_dir/file.$file_id.ttl.txt";
    if (!(-e $file)) {
        print "no such file: $file\n";
        next;
    }
    print `date`;
    print "  $file\n";


    #####
    ## open file 
    ##   format: <IP> <# TTL> <TTL1> <TTL2> <TTL3> ...
    open FH, $file or die $!;
    while(<FH>) {
        my ($ip_pair, $ttl_cnt, @ttls) = split(/, /, $_);
        $ttl_cnt += 0;
        die "wrong format\n" if($ttl_cnt != scalar(@ttls));


        ## filter out destination IPs (not start by 28.xxx.xxx.xxx)
        if(!($ip_pair =~ /^28\./)) {
            # print "skip $ip_pair\n";
            next;
        }


        ## a new client
        $cnt_clients ++;


        ## normal client
        if($ttl_cnt == 1) {
            my $this_ttl = (shift @ttls) + 0;

            $ttl_info{TTL}{$this_ttl}{CNT} ++;
            $ttl_info{NORMAL_TTL}{$this_ttl}{CNT} ++;
        }
        ## tethered client
        elsif($ttl_cnt > 1) {
            foreach my $this_ttl (@ttls) {
                $this_ttl += 0;
                
                $ttl_info{TTL}{$this_ttl}{CNT} ++;
                $ttl_info{TETHER_TTL}{$this_ttl}{CNT} ++;
            }

            ## calculate the diff of TTLs
            if($ttl_cnt == 2) {
                my $ttl_diff = abs($ttls[0] - $ttls[1]);
                $ttl_info{TTL_DIFF}{$ttl_diff}{CNT} ++;
            }
        }

        else {
            die "weird TTL count\n";
        }
        
    }
    close FH;
}


#####
## output

## - ttl_all_dist.txt
##   <TTL> <count>
open FH, "> $output_dir/$file_all_dist" or die $!;
foreach my $this_ttl (min(keys %{ $ttl_info{TTL} }) .. max(keys %{ $ttl_info{TTL} }) ) {
    if(exists $ttl_info{TTL}{$this_ttl}) {
        print FH $this_ttl.", ".$ttl_info{TTL}{$this_ttl}{CNT}."\n";
    }
    else {
        print FH $this_ttl.", 0\n";
    }
}
close FH;

## - ttl_normal_dist.txt
##   <TTL> <count>
open FH, "> $output_dir/$file_normal_dist" or die $!;
foreach my $this_ttl (min(keys %{ $ttl_info{NORMAL_TTL} }) .. max(keys %{ $ttl_info{NORMAL_TTL} }) ) {
    if(exists $ttl_info{NORMAL_TTL}{$this_ttl}) {
        print FH $this_ttl.", ".$ttl_info{NORMAL_TTL}{$this_ttl}{CNT}."\n";
    }
    else {
        print FH $this_ttl.", 0\n";
    }
}
close FH;

## - ttl_tether_dist.txt
##   <TTL> <count>
open FH, "> $output_dir/$file_tether_dist" or die $!;
foreach my $this_ttl (min(keys %{ $ttl_info{TETHER_TTL} }) .. max(keys %{ $ttl_info{TETHER_TTL} }) ) {
    if(exists $ttl_info{TETHER_TTL}{$this_ttl}) {
        print FH $this_ttl.", ".$ttl_info{TETHER_TTL}{$this_ttl}{CNT}."\n";
    }
    else {
        print FH $this_ttl.", 0\n";
    }
}
close FH;

## - ttl_diff.txt
##   <TTL diff> <count>
open FH, "> $output_dir/$file_diff" or die $!;
foreach my $this_ttl (min(keys %{ $ttl_info{TTL_DIFF} }) .. max(keys %{ $ttl_info{TTL_DIFF} }) ) {
    if(exists $ttl_info{TTL_DIFF}{$this_ttl}) {
        print FH $this_ttl.", ".$ttl_info{TTL_DIFF}{$this_ttl}{CNT}."\n";
    }
    else {
        print FH $this_ttl.", 0\n";
    }
}
close FH;


## plot figure
system("gnuplot plot_ttl_dist.plot");

1;

