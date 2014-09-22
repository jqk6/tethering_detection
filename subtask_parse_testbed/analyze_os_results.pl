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
my $input_dir  = "../processed_data/subtask_parse_testbed/statistics";
my $output_dir = "../processed_data/subtask_parse_testbed/statistics";

my $ratio = 0.3;
my @filenames = (
            "results.os.testbed.exp2.filter.dup1.host$ratio.bt0.s1--testbed.exp3.filter.dup1.host$ratio.bt0.s1.txt"
            , "results.os.testbed.exp4.filter.dup1.host$ratio.bt0.s1--testbed.exp5.filter.dup1.host$ratio.bt0.s1.txt"
            , "results.os.testbed.exp6.filter.dup1.host$ratio.bt0.s1--testbed.exp7.filter.dup1.host$ratio.bt0.s1.txt"
            , "results.os.testbed.exp8.filter.dup1.host$ratio.bt0.s1--testbed.exp9.filter.dup1.host$ratio.bt0.s1.txt"
            , "results.os.testbed.exp10.filter.dup1.host$ratio.bt0.s1--testbed.exp11.filter.dup1.host$ratio.bt0.s1.txt"
    );
my @oss = ("Android", "Apple", "Windows");

my %prob_info = ();
my %pred_info = ();
foreach my $this_os (@oss) {
    $pred_info{OS}{$this_os}{TP} = 0;
    $pred_info{OS}{$this_os}{TN} = 0;
    $pred_info{OS}{$this_os}{FP} = 0;
    $pred_info{OS}{$this_os}{FN} = 0;
}


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

foreach my $filename (@filenames) {
    open FH, "$input_dir/$filename" or die $!;
    <FH>;
    while(<FH>) {
        chomp;
        my @tmp = split(", ", $_);
        my $os = "";
        foreach my $this_os (@oss) {
            $os = $this_os if($tmp[0] =~ /$this_os/);
        }
        die if($os eq "");

        ## TTL128
        my $feature_name = "TTL128";
        my $ind = 3;
        my $num_val = 2;
        update_prob_info($feature_name, $os, \%prob_info, \@tmp, $ind, $num_val);

        ## IP_ID_mono
        $feature_name = "IP_ID_mono";
        $ind = 11;
        $num_val = 4;
        update_prob_info($feature_name, $os, \%prob_info, \@tmp, $ind, $num_val);

        ## WSF
        $feature_name = "WSF";
        $ind = 27;
        $num_val = 6;
        update_prob_info($feature_name, $os, \%prob_info, \@tmp, $ind, $num_val);

        ## TS ratio
        $feature_name = "TS_ratio";
        $ind = 51;
        $num_val = 3;
        update_prob_info($feature_name, $os, \%prob_info, \@tmp, $ind, $num_val);
        
        ## freq
        $feature_name = "freq";
        $ind = 63;
        $num_val = 6;
        update_prob_info($feature_name, $os, \%prob_info, \@tmp, $ind, $num_val);

        ## freq stdev
        $feature_name = "freq stdev";
        $ind = 87;
        $num_val = 3;
        update_prob_info($feature_name, $os, \%prob_info, \@tmp, $ind, $num_val);

        ## combine
        $feature_name = "combine";
        $ind = 98;
        $num_val = 1;
        update_prob_info($feature_name, $os, \%prob_info, \@tmp, $ind, $num_val);


        
    }
    close FH;
}


foreach my $this_f (keys %{ $pred_info{FEATURE} }) {
    open FH, "> $output_dir/eval.os_detect.$this_f.txt" or die $!;
    
    my $accuracy = $pred_info{FEATURE}{$this_f}{ACCURACY} / $pred_info{FEATURE}{$this_f}{CNT};
    print "\n$this_f, $accuracy\n";
    print FH "# $this_f, $accuracy\n";


    foreach my $this_os (@oss) {
        my $precision = MyUtil::precision($pred_info{FEATURE}{$this_f}{OS}{$this_os}{TP}, 
                                          $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FN}, 
                                          $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FP}, 
                                          $pred_info{FEATURE}{$this_f}{OS}{$this_os}{TN});
        my $recall = MyUtil::recall($pred_info{FEATURE}{$this_f}{OS}{$this_os}{TP}, 
                                    $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FN}, 
                                    $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FP}, 
                                    $pred_info{FEATURE}{$this_f}{OS}{$this_os}{TN});
        print "$this_os, $precision, $recall\n";
        print FH "$this_os $precision $recall\n";
    }
    close FH;
}

1;



sub update_prob_info {
    my ($feature_name, $os, $prob_info_ref, $feaure_val_ref, $ind, $num_val) = @_;
    
    my $DEBUG0 = 0;

    my %prob_info = %$prob_info_ref;
    my @tmp = @$feaure_val_ref;
    my @oss = ("Android", "Apple", "Windows");

    $prob_info{FEATURE}{$feature_name}{OS}{"Android"} = 1;
    $prob_info{FEATURE}{$feature_name}{OS}{"Apple"} = 1;
    $prob_info{FEATURE}{$feature_name}{OS}{"Windows"} = 1;
    foreach my $i (0 .. $num_val-1) {
        my $this_ind = $ind + $i * 4;
        if($tmp[$this_ind] ne "X") {
            $prob_info{FEATURE}{$feature_name}{OS}{"Android"} *= $tmp[$this_ind];
        }

        $this_ind = $ind + $i * 4 + 1;
        if($tmp[$this_ind] ne "X") {
            $prob_info{FEATURE}{$feature_name}{OS}{"Apple"} *= $tmp[$this_ind];
        }

        $this_ind = $ind + $i * 4 + 2;
        if($tmp[$this_ind] ne "X") {
            $prob_info{FEATURE}{$feature_name}{OS}{"Windows"} *= $tmp[$this_ind];
        }
    }
    print "$os: $feature_name (".join("|", ($prob_info{FEATURE}{$feature_name}{OS}{"Android"}, $prob_info{FEATURE}{$feature_name}{OS}{"Apple"}, $prob_info{FEATURE}{$feature_name}{OS}{"Windows"})).")\n" if($DEBUG0);


    my @sorted_os = sort {$prob_info{FEATURE}{$feature_name}{OS}{$b} <=> $prob_info{FEATURE}{$feature_name}{OS}{$a}} @oss;
    my $predicted_os = "";
    if($prob_info{FEATURE}{$feature_name}{OS}{$sorted_os[0]} > 0){
        $predicted_os = $sorted_os[0];
    }
    print "  prediction: ".join(">", @sorted_os)."\n" if($DEBUG0);

    $pred_info{FEATURE}{$feature_name}{CNT} ++;
    if($predicted_os eq $os) {
        $pred_info{FEATURE}{$feature_name}{OS}{$os}{TP} ++;
        $pred_info{FEATURE}{$feature_name}{ACCURACY} ++;
    }
    elsif($predicted_os ne "") {
        $pred_info{FEATURE}{$feature_name}{OS}{$os}{FN} ++;
        $pred_info{FEATURE}{$feature_name}{OS}{$predicted_os}{FP} ++;
    }
    else {
        $pred_info{FEATURE}{$feature_name}{OS}{$os}{FN} ++;
    }
}






