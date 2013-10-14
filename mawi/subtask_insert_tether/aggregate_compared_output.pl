#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2013.09.27 @ UT Austin
##
## - input:
##      1. trace_name
##      2. exp
##
## - output:
##
## - e.g.
##      perl aggregate_compared_output.pl 201101091400.dump exp0
##
##########################################

use strict;

#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print output
my $DEBUG4 = 1; ## parse heuristic name and parameter values


#############
# Constants
#############


#############
# Variables
#############
my $input_dir = "../../processed_data/mawi/subtask_tethering_detection/tether_ips_compare";
my $output_dir = "";

my $trace_name = "201101091400.dump";
my $exp = "exp0";

my %results = ();

#############
# check input
#############
if(@ARGV != 2) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$trace_name = $ARGV[0];
$exp = $ARGV[1];
print "trace: $trace_name, exp: $exp\n" if($DEBUG2);


#############
# Main starts
#############

print "find all results of this trace\n" if($DEBUG2);
opendir(DIR, $input_dir) or die $!;
while (my $file = readdir(DIR)) {
    next if($file =~ /^\.+/);  ## don't show "." and ".."
    next if(-d "$input_dir/$file");  ## don't show directories

    if($file =~ /$trace_name\.txt\.$exp.txt.(.*).txt$/) {
        my $heuristic = $1;
        print "  - $file:\n    $heuristic\n" if($DEBUG2);

        ## parse heuristic
        my @tmp = split(/\./, $heuristic);
        my $heuristic_name = shift @tmp;
        my $heuristic_para = join(".", @tmp);
        print "      name = $heuristic_name\n" if($DEBUG4);
        print "      parameters = $heuristic_para\n" if($DEBUG4);

        ## parse parameters
        my $results_ref = \%{ $results{HEURISTIC}{$heuristic_name}{PARAMETER} };
        foreach my $this_para (@tmp) {
            print "        $this_para: " if($DEBUG4);

            if($this_para =~ /^(\D+)(\d+\.*\d*)$/) {
                my $para_name = $1;
                my $para_value = $2 + 0;

                print "$para_name = $para_value\n" if($DEBUG4);

                unless(exists $results_ref->{$para_name}{$para_value}) {
                    $results_ref->{$para_name}{$para_value} = ();
                }
                $results_ref = \%{ $results_ref->{$para_name}{$para_value} };
            }
            else {
                die "wrong parameters format\n";
            }
        }

        ## record the results
        open FH, "$input_dir/$file" or die $!;
        while(<FH>) {
            ## should be just 1 line: [TP, TN, FP, FN, precision, recall, f1_score]
            my ($tp, $tn, $fp, $fn, $precision, $recall, $f1_score) = split(/,/, $_);
            $tp += 0; $tn += 0; $fp += 0; $fn += 0; $precision += 0; $recall += 0; $f1_score += 0;

            print "    $tp, $tn, $fp, $fn, $precision, $recall, $f1_score\n" if($DEBUG1);
            # $results{HEURISTIC}{$heuristic_name}{PARAMETER}{$heuristic_para}{TP} = $tp;
            # $results{HEURISTIC}{$heuristic_name}{PARAMETER}{$heuristic_para}{TN} = $tn;
            # $results{HEURISTIC}{$heuristic_name}{PARAMETER}{$heuristic_para}{FP} = $fp;
            # $results{HEURISTIC}{$heuristic_name}{PARAMETER}{$heuristic_para}{FN} = $fn;
            # $results{HEURISTIC}{$heuristic_name}{PARAMETER}{$heuristic_para}{PRECISION} = $precision;
            # $results{HEURISTIC}{$heuristic_name}{PARAMETER}{$heuristic_para}{RECALL} = $recall;
            # $results{HEURISTIC}{$heuristic_name}{PARAMETER}{$heuristic_para}{F1} = $f1_score;
            
            $results_ref->{TP} = $tp;
            $results_ref->{TN} = $tn;
            $results_ref->{FP} = $fp;
            $results_ref->{FN} = $fn;
            $results_ref->{PRECISION} = $precision;
            $results_ref->{RECALL} = $recall;
            $results_ref->{F1} = $f1_score;
        }
        close FH;
    }
}
closedir(DIR);



#############
# Print out results
#############
print "\nPrint out results\n" if($DEBUG2);
print "clean\n" if($DEBUG2);
foreach my $heuristic_name (sort {$a cmp $b} (keys %{ $results{HEURISTIC} }) ) {
    # print "$heuristic_name\n";
    print_heuristic(\%{ $results{HEURISTIC}{$heuristic_name}{PARAMETER} }, "$heuristic_name, ", 1);
    # print "\n";
}
print "not clean\n" if($DEBUG2);
foreach my $heuristic_name (sort {$a cmp $b} (keys %{ $results{HEURISTIC} }) ) {
    print_heuristic(\%{ $results{HEURISTIC}{$heuristic_name}{PARAMETER} }, "$heuristic_name, ", 0);
}


sub print_heuristic {
    my ($results_ref, $para_so_far, $discard) = @_;

    if(exists $results_ref->{TP}) {
        # return ("", $results_ref->{TP});
        if($para_so_far =~ /discard=$discard/) {
            print "$para_so_far, ".join(", ", 
                ($results_ref->{TP}, 
                 $results_ref->{TN},
                 $results_ref->{FP},
                 $results_ref->{FN},
                 $results_ref->{PRECISION},
                 $results_ref->{RECALL},
                 $results_ref->{F1}) )."\n";
        }
        return;
    }

    foreach my $para_name (sort {$a cmp $b} (keys %$results_ref) ) {
        foreach my $para_value (sort {$a <=> $b} (keys %{ $results_ref->{$para_name} })) {
            # print "> $para_name=$para_value\n";

            my $this_para_so_far = $para_so_far . "$para_name=$para_value";
            $this_para_so_far .= "." if($para_name ne "discard");



            print_heuristic(\%{ $results_ref->{$para_name}{$para_value} }, $this_para_so_far, $discard);
        }
    }
}