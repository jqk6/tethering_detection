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
##   
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use lib "/u/yichao/utils/perl";
use lib "../utils";

use MyUtil;

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
my $input_dir  = "../processed_data/subtask_parse_testbed/detection";
my $output_dir = "../processed_data/subtask_parse_testbed/detection";

my $ratio = 0.3;
my @train_filenames = ("testbed.exp2.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp4.filter.dup1.host0.3.bt0.s1.svm.txt"
                 # , "testbed.exp6.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp8.filter.dup1.host0.3.bt0.s1.svm.txt"
                 # , "testbed.exp10.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp1.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp1.filter.dup1.host0.3.bt0.s1.svm.txt"
                 # , "testbed.exp1.filter.dup1.host0.3.bt0.s1.svm.txt"
                 );
my @test_filenames  = ("testbed.exp3.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp5.filter.dup1.host0.3.bt0.s1.svm.txt"
                 # , "testbed.exp7.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp9.filter.dup1.host0.3.bt0.s1.svm.txt"
                 # , "testbed.exp11.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp3.filter.dup1.host0.3.bt0.s1.svm.txt"
                 , "testbed.exp6.filter.dup1.host0.3.bt0.s1.svm.txt"
                 # , "testbed.exp10.filter.dup1.host0.3.bt0.s1.svm.txt"
                 );

my $tp = 0;
my $tn = 0;
my $fp = 0;
my $fn = 0;

my %result_info;


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

my @precs;
my @recalls;
foreach my $fi (0 .. @train_filenames-1) {
    my $filename = $train_filenames[$fi]."--".$test_filenames[$fi];

    #####
    ## ground truth
    my @gt;
    open FH, "$input_dir/".$test_filenames[$fi] or die $!;
    while(<FH>) {
        chomp;
        my ($is_tether, @tmp) = split(" ", $_);
        # print $is_tether."\n";

        push(@gt, $is_tether+0);
    }
    close FH;


    #####
    ## prediction
    my @pred;
    my @pred_prob;
    open FH, "$input_dir/$filename.predict" or die $!."\n$filename.predict\n";
    <FH>;
    while(<FH>) {
        chomp;
        my ($is_tether, $prob, $tmp) = split(/ /, $_);
        # print "$is_tether: $prob\n";

        push(@pred, $is_tether+0);
        push(@pred_prob, $prob+0);
    }
    close FH;

    #####
    ## evaluate
    my $tp = 0;
    my $tn = 0;
    my $fp = 0;
    my $fn = 0;
    foreach my $i (0 .. @gt-1) {
        if($gt[$i] == 1 and $pred[$i] == 1) {
            $tp ++
        }
        elsif($gt[$i] == 1 and $pred[$i] == 0) {
            $fn ++
        }
        elsif($gt[$i] == 0 and $pred[$i] == 1) {
            $fp ++
        }
        elsif($gt[$i] == 0 and $pred[$i] == 0) {
            $tn ++
        }
    }
    my $precision = MyUtil::precision($tp, $fn, $fp, $tn);
    my $recall = MyUtil::recall($tp, $fn, $fp, $tn);
    print "$tp, $tn, $fp, $fn, $precision, $recall\n";

    push(@precs, $precision);
    push(@recalls, $recall);
}

print "avg precision=".MyUtil::average(\@precs)."\n";
print "avg recall=".MyUtil::average(\@recalls)."\n";



1;


