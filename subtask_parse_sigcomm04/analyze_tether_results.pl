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
my $prec_thresh = 0.9;

#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_parse_sigcomm04/statistics";
my $output_dir = "../processed_data/subtask_parse_sigcomm04/statistics";

my $basename = "chihuahuan-ath2.03";
my @filenames;
my $ratio = 0.3;
foreach my $i (1 .. 5) {
    foreach my $j (1 .. 5) {
        push(@filenames, "results.tether.$basename.filter.dup1.host$ratio.bt0.s$i--$basename.filter.dup1.host0.3.bt0.s$j.txt");
    }
}

# my @filenames = ("results.tether.sigcomm08.exp2.filter.dup1.host$ratio.bt0.s1--sigcomm08.exp3.filter.dup1.host$ratio.bt0.s1.txt");

my $tp = 0;
my $tn = 0;
my $fp = 0;
my $fn = 0;

my %result_info;


#############
# check input
#############
# if(@ARGV != 0) {
#     print "wrong number of input: ".@ARGV."\n";
#     exit;
# }
if(@ARGV == 1) {
    $prec_thresh = $ARGV[0]+0;
}



#############
# Main starts
#############

my %features;

foreach my $filename (@filenames) {
    my %prob_info = ();

    print "================================== $filename\n";

    open FH, "$input_dir/$filename" or die "$filename";
    <FH>;
    while(<FH>) {
        chomp;
        my @tmp = split(", ", $_);
        my $is_tether = 0;
        my ($ip, $is_tether);
        if($tmp[0] =~ /(.*)=(\d)/) {
            $ip = $1;
            $is_tether = $2 + 0;
        }
        else {
            die "wrong format: ".$tmp[0]."\n";
        }
        # print "> ".$tmp[0]." = $ip  +  $is_tether\n";
        $is_tether += 0;

        ##  TTL number=1
        my $feature_name = "TTL number";
        $features{$feature_name} = 1;
        my $ind = 3;
        my $num_val = 2;
        update_prob_info($feature_name, $ip, $is_tether, \%prob_info, \@tmp, $ind, $num_val);

        ## TS mono - ratio of violating pkts
        $feature_name = "TS mono - ratio of violating pkts";
        $features{$feature_name} = 1;
        $ind = 7;
        $num_val = 2;
        update_prob_info($feature_name, $ip, $is_tether, \%prob_info, \@tmp, $ind, $num_val);

        ## TS mono - number of large TS itvl
        $feature_name = "TS mono - number of large TS itvl";
        $features{$feature_name} = 1;
        $ind = 11;
        $num_val = 2;
        update_prob_info($feature_name, $ip, $is_tether, \%prob_info, \@tmp, $ind, $num_val);

        ##  freq stdev
        $feature_name = "freq stdev";
        $features{$feature_name} = 1;
        $ind = 15;
        $num_val = 3;
        update_prob_info($feature_name, $ip, $is_tether, \%prob_info, \@tmp, $ind, $num_val);

        ## boot time stdev
        $feature_name = "boot time stdev";
        $features{$feature_name} = 1;
        $ind = 21;
        $num_val = 3;
        update_prob_info($feature_name, $ip, $is_tether, \%prob_info, \@tmp, $ind, $num_val);

        ## OS
        $feature_name = "OS";
        $features{$feature_name} = 1;
        $ind = 26;
        $prob_info{IP}{$ip}{FEATURE}{$feature_name}{PROB} = 1-max($tmp[$ind], $tmp[$ind+1], $tmp[$ind+2]);
        
        ## Combine1
        $feature_name = "Combine1";
        $features{$feature_name} = 1;
        $ind = 29;
        $prob_info{IP}{$ip}{FEATURE}{$feature_name}{PROB} = $tmp[$ind];

        ## Combine2
        $feature_name = "Combine2";
        $features{$feature_name} = 1;
        $ind = 30;
        $prob_info{IP}{$ip}{FEATURE}{$feature_name}{PROB} = $tmp[$ind];
    }
    close FH;

    ## evaluation
    # print "\n- evaluation\n";
    
    foreach my $feature_name (sort keys %features) {
        # my $tpr = eval_results($feature_name, \%prob_info, $fpr_thresh);
        my ($best_prec, $best_recall) = eval_results2($feature_name, \%prob_info, $prec_thresh);
        push(@{ $result_info{FEATURE}{$feature_name}{PREC} }, $best_prec);
        push(@{ $result_info{FEATURE}{$feature_name}{RECALL} }, $best_recall);
    }
}

foreach my $feature_name (sort keys %features) {
    # print "$feature_name: prec=".MyUtil::average(\@{ $result_info{FEATURE}{$feature_name}{PREC} })
    #                 .", recall=".MyUtil::average(\@{ $result_info{FEATURE}{$feature_name}{RECALL} })."\n";
    print "$feature_name, ".MyUtil::average(\@{ $result_info{FEATURE}{$feature_name}{PREC} })
                    .", ".max(@{ $result_info{FEATURE}{$feature_name}{PREC} })
                    .", ".MyUtil::average(\@{ $result_info{FEATURE}{$feature_name}{RECALL} })
                    .", ".max(@{ $result_info{FEATURE}{$feature_name}{RECALL} })."\n"; 
}




# foreach my $this_f (keys %{ $pred_info{FEATURE} }) {
#     open FH, "> $output_dir/eval.os_detect.$this_f.txt" or die $!;
    
#     my $accuracy = $pred_info{FEATURE}{$this_f}{ACCURACY} / $pred_info{FEATURE}{$this_f}{CNT};
#     print "\n$this_f, $accuracy\n";
#     print FH "# $this_f, $accuracy\n";


#     foreach my $this_os (@oss) {
#         my $precision = MyUtil::precision($pred_info{FEATURE}{$this_f}{OS}{$this_os}{TP}, 
#                                           $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FN}, 
#                                           $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FP}, 
#                                           $pred_info{FEATURE}{$this_f}{OS}{$this_os}{TN});
#         my $recall = MyUtil::recall($pred_info{FEATURE}{$this_f}{OS}{$this_os}{TP}, 
#                                     $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FN}, 
#                                     $pred_info{FEATURE}{$this_f}{OS}{$this_os}{FP}, 
#                                     $pred_info{FEATURE}{$this_f}{OS}{$this_os}{TN});
#         print "$this_os, $precision, $recall\n";
#         print FH "$this_os $precision $recall\n";
#     }
#     close FH;
# }

1;



sub update_prob_info {
    my ($feature_name, $ip, $is_tether, $prob_info_ref, $feaure_val_ref, $ind, $num_val) = @_;
    
    my $DEBUG0 = 0;

    my @tmp = @$feaure_val_ref;
    
    $prob_info_ref->{IP}{$ip}{TETHER} = $is_tether;
    $prob_info_ref->{IP}{$ip}{FEATURE}{$feature_name}{PROB} = 1;
    foreach my $i (0 .. $num_val-1) {
        my $this_ind = $ind + $i * 2;
        if($tmp[$this_ind] ne "X") {
            $prob_info_ref->{IP}{$ip}{FEATURE}{$feature_name}{PROB} *= $tmp[$this_ind];
        }
    }
    print "$ip - $is_tether: $feature_name (".($prob_info_ref->{IP}{$ip}{FEATURE}{$feature_name}{PROB}).")\n" if($DEBUG0);

}


sub eval_results {
    my ($feature_name, $prob_info_ref, $fpr_thresh) = @_;

    my $DEBUG0 = 1;
    print "> $feature_name\n" if($DEBUG0);

    my @probs = ();
    foreach my $this_ip (sort keys %{ $prob_info_ref->{IP} }) {
        push(@probs, $prob_info_ref->{IP}{$this_ip}{FEATURE}{$feature_name}{PROB});
    }
    
    my %seen;
    my $best_tpr = 0;
    foreach my $thresh (grep { ! $seen{$_}++ } sort {$a <=> $b} @probs) {
        my $tp = 0;
        my $tn = 0;
        my $fp = 0;
        my $fn = 0;

        foreach my $this_ip (sort keys %{ $prob_info_ref->{IP} }) {
            my $is_tether = $prob_info_ref->{IP}{$this_ip}{TETHER};
            my $tether_prob = $prob_info_ref->{IP}{$this_ip}{FEATURE}{$feature_name}{PROB};

            if($tether_prob >= $thresh) {
                ## predict as tethering
                if($is_tether) { $tp ++; }
                else { $fp ++; }
            }
            else {
                ## predict as normal
                if($is_tether) { $fn ++; }
                else { $tn ++; }
            }
        }

        my $prec = MyUtil::precision($tp, $fn, $fp, $tn);
        my $recall = MyUtil::recall($tp, $fn, $fp, $tn);
        my $f1 = 0; $f1 = MyUtil::f1_score($prec, $recall) if($prec + $recall > 0);
        my $fpr = $fp / ($fp + $tn);
        if($fpr <= $fpr_thresh and $recall > $best_tpr) {
            $best_tpr = $recall;
        } 
        print "  $thresh, $tp, $tn, $fp, $fn, $prec, $recall, $f1, $fpr\n" if($DEBUG0);
    }

    return $best_tpr;
}


sub eval_results2 {
    my ($feature_name, $prob_info_ref, $prec_thresh) = @_;

    my $DEBUG0 = 1;
    print "> $feature_name\n" if($DEBUG0);

    my @probs = ();
    foreach my $this_ip (sort keys %{ $prob_info_ref->{IP} }) {
        push(@probs, $prob_info_ref->{IP}{$this_ip}{FEATURE}{$feature_name}{PROB});
    }
    
    my %seen;
    my $best_recall = 0;
    my $best_prec = 0;
    foreach my $thresh (grep { ! $seen{$_}++ } sort {$a <=> $b} @probs) {
        my $tp = 0;
        my $tn = 0;
        my $fp = 0;
        my $fn = 0;

        foreach my $this_ip (sort keys %{ $prob_info_ref->{IP} }) {
            my $is_tether = $prob_info_ref->{IP}{$this_ip}{TETHER};
            my $tether_prob = $prob_info_ref->{IP}{$this_ip}{FEATURE}{$feature_name}{PROB};

            if($tether_prob >= $thresh) {
                ## predict as tethering
                if($is_tether) { $tp ++; }
                else { $fp ++; }
            }
            else {
                ## predict as normal
                if($is_tether) { $fn ++; }
                else { $tn ++; }
            }
        }

        my $prec = MyUtil::precision($tp, $fn, $fp, $tn);
        my $recall = MyUtil::recall($tp, $fn, $fp, $tn);
        my $f1 = 0; $f1 = MyUtil::f1_score($prec, $recall) if($prec + $recall > 0);
        my $fpr = $fp / ($fp + $tn);
        if($prec >= $prec_thresh and $recall > $best_recall) {
            $best_recall = $recall;
            $best_prec = $prec;
        } 
        print "  $thresh, tp=$tp, fn=$tn, fp=$fp, fn=$fn, prec=$prec, recall=$recall, f1=$f1, fpt=$fpr\n" if($DEBUG0);
    }

    return ($best_prec, $best_recall);
}





