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
my $input_dir  = "../processed_data/subtask_parse_sigcomm08/detection";
my $output_dir = "../processed_data/subtask_parse_sigcomm08/detection";

my $ratio = 0.3;
my @filenames = (
                   "train5.test1.weka.txt"
                 , "train5.test2.weka.txt"
                 , "train5.test5.weka.txt"
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
foreach my $filename (@filenames) {
    
    my $precision;
    my $recall;
    my $first = 1;
    open FH, "$input_dir/$filename" or die $!."\n  $input_dir/$filename\n";
    while(<FH>) {
        chomp;
        next unless($_ =~ /TP Rate   FP Rate   Precision   Recall  F-Measure   ROC Area  Class/);
        if($first) {
            $first = 0;
            next;
        }
        my $line = <FH>;
        chomp;
        my @data = split(/\s+/, $line);
        print ">".join("|", @data)."<\n";
        $precision = $data[3];
        $recall = $data[4];
        last;
    }
    close FH;
    
    push(@precs, $precision);
    push(@recalls, $recall);
}

# print "avg precision=".MyUtil::average(\@precs)."\n";
# print "avg recall=".MyUtil::average(\@recalls)."\n";
print MyUtil::average(\@precs).", ".MyUtil::average(\@recalls)."\n";


1;


