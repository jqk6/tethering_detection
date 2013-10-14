#!/bin/perl 

use strict;


## output
##  a) ./tethered_clients/summary.number_methods.txt
##      format:
##      <# tethered clients detected by 1 method>, <ratio>, 
##      <# tethered clients detected by 2 methods>, <ratio>, 
##      <# tethered clients detected by 3 methods>, <ratio>, 
##      ...
##
##  b) ./tethered_clients/summary.cross_validation.txt
##      <method1> <method2> <# overlap> <# former> <# latter> <# tethered clients> <ratio overlap> <ratio former> <ratio latter>
##      <method1> <method3> <# overlap> <# former> <# latter> <# tethered clients> <ratio overlap> <ratio former> <ratio latter>
##      <method2> <method3> <# overlap> <# former> <# latter> <# tethered clients> <ratio overlap> <ratio former> <ratio latter>
##      ...
##  
open FH_SUMMARY_NUM,     "> ./tethered_clients/summary.number_methods.txt";
open FH_SUMMARY_OVERLAP, "> ./tethered_clients/summary.cross_validation.txt";

my $done = 0;

foreach my $file_id (49 .. 199, 0 .. 48) {
    my $file_num     = "./tethered_clients/summary.$file_id.number_methods.txt";
    my $file_overlap = "./tethered_clients/summary.$file_id.cross_validation.txt";
    if (!(-e $file_num) or !(-e $file_overlap)) {
        print "no such file: $file_num or $file_overlap\n";
        next;
    }
    print `date`;
    print "  $file_num\n";


    #####
    ## number of methods
    open FH, $file_num or die $!;
    while(<FH>) {
        ## <number of methods> <number of tethered clients>
        my ($number_methods, $num_tethered_clients, $ratio_tethered_clients) = split(/, /, $_);
        $number_methods += 0;
        $num_tethered_clients += 0;
        $ratio_tethered_clients += 0;

        print FH_SUMMARY_NUM "$num_tethered_clients, $ratio_tethered_clients, ";
    }
    close FH;
    print FH_SUMMARY_NUM "\n";


    #####
    ## cross validation
    open FH, $file_overlap or die $!;
    while(<FH>) {
        ## <method1> <method2> <overlap> <only by former> <only by latter> <# total detected clients> <overlap ratio> <only by former ratio> <only by latter ratio>
        my @all = split(/, /, $_);
        for (2 .. scalar(@all)-1) {
            $all[$_] += 0;
        }
        
        print FH_SUMMARY_OVERLAP join(", ", @all).", ";
    }
    close FH;
    print FH_SUMMARY_OVERLAP "\n";
}

close FH_SUMMARY_NUM;
close FH_SUMMARY_OVERLAP;


