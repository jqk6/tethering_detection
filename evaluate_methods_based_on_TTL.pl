#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/18 @ Narus 
##
## There are many methods to detect tehtering.
## This program use TTL heuristic as ground truth, 
##   and calculate precision and recall of other methods with various parameters (e.g. diff thresholds)
##
## - input: 
##     ./tethered_clients/
##     IP of tethered clients
##      a) TTL (whole trace)         : TTL_whole_trace.<file id>.txt
##      b) TTL (one second)          : TTL_one_second.<file id>.txt
##      c) Connections               : Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 5, 10, 60, 600)
##                                     Thresholds = (2 .. 30)
##      d) RTT (variance)            : RTT_variance.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, .. , 0.8)
##      e) Inter-arrival time (mean) : Inter_arrival_time_mean.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.005, 0.01, 0.02, 0.03, 0.05, .. , 4)
##      f) Inter-arrival time (stdev): Inter_arrival_time_stdev.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.005, 0.01, 0.15, 0.2, 0.25, .. , 10)
##      g) Throughput                : Tput_whole_trace.threshold<threshold>.<file id>.txt
##                                     Thresholds = (10, 15, 20, 25, 30, 40, 50, 60, .. , 10000)
##      h) Pkt length Entropy        : Pkt_len_entropy.timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 600)
##                                     Thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, .. , 2)
##
## - output:
##      PR curve (Precision-Recall)
##      ./tethered_clients/process_output/
##        format:
##        <threshold> <TP> <FN> <FP> <TN> <precision> <recall>
##
##  e.g.
##      perl evaluate_methods_based_on_TTL.pl 49
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
my $input_dir = "./tethered_clients";
my $input_all_client_dir = "./output";
my $output_dir = "./tethered_clients/process_output";
my $based_method = "TTL_one_second";
    # possible base: "TTL_one_second", "TTL_whole_trace"

my $file_id;

my %tether_info;        ## to store the information of tethered IP
                        ## {IP}{ip}{METHOD}{methods}
                        ## {METHOD}{method}{TP}{tp}
                        ## {METHOD}{method}{FN}{fn}
                        ## {METHOD}{method}{FP}{fp}
                        ## {METHOD}{method}{TN}{tn}
                        ## {METHOD}{method}{PRECISION}{precision}
                        ## {METHOD}{method}{RECALL}{recall}


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);



#####
## main starts here

#####
## read in all IPs
my $file_name = "file.$file_id.ttl.txt";
open FH, "$input_all_client_dir/$file_name" or die $!;
while(<FH>) {
    my ($ip, @others) = split(/, /, $_);

    %{ $tether_info{IP}{$ip} } = ();
}
close FH;

#####
## DEBUG
#####
if($DEBUG1) {
    foreach my $this_ip (keys %{ $tether_info{IP} }) {
        print $this_ip."\n";
    }
}


##############################################################################
## detected IPs of each method
##############################################################################


##############################################################################
## a) TTL (whole trace): TTL_whole_trace.<file id>.txt
my $method_name = "TTL_whole_trace";
$file_name = "$method_name.$file_id.txt";
open FH, "$input_dir/$file_name" or die $!;
while(my $this_ip = <FH>) {
    chomp $this_ip;
    print $this_ip."\n" if($DEBUG1);


    ## DEBUG
    die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

    $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
}
close FH;


##############################################################################
## b) TTL (one second) : TTL_one_second.<file id>.txt
$method_name = "TTL_one_second";
$file_name = "$method_name.$file_id.txt";
open FH, "$input_dir/$file_name" or die $!;
while(my $this_ip = <FH>) {
    chomp $this_ip;
    print $this_ip."\n" if($DEBUG1);


    ## DEBUG
    die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

    $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
}
close FH;


##############################################################################
## c) Connections: Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                 Time bins  = (1, 5, 10, 60, 600)
##                 Thresholds = (2 .. 30)
my @conntions_time_bins = (1, 5, 10, 60, 600);
my @connections_thresholds = (2 .. 30);
foreach my $this_timebin (@conntions_time_bins) {
    my $conn_output_file = "Connections_timebin$this_timebin.PR.$file_id.txt";
    open FH_PR, "> $output_dir/$conn_output_file" or die $!;

    foreach my $this_threshold (@connections_thresholds) {
        $method_name = "Connections_timebin$this_timebin.threshold$this_threshold";
        $file_name = "$method_name.$file_id.txt";
        

        #####
        ## read in data
        open FH, "$input_dir/$file_name" or die $!;
        while(my $this_ip = <FH>) {
            chomp $this_ip;
            print $this_ip."\n" if($DEBUG1);


            ## DEBUG
            die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

            $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
        }
        close FH;


        #####
        ## statistics
        (
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        ) = cal_confusion_matrix($based_method, $method_name, \%tether_info);

        $tether_info{METHOD}{$method_name}{PRECISION} = MyUtil::precision(
             $tether_info{METHOD}{$method_name}{TP}, 
             $tether_info{METHOD}{$method_name}{FN}, 
             $tether_info{METHOD}{$method_name}{FP}, 
             $tether_info{METHOD}{$method_name}{TN}
            );
        $tether_info{METHOD}{$method_name}{RECALL} = MyUtil::recall(
             $tether_info{METHOD}{$method_name}{TP}, 
             $tether_info{METHOD}{$method_name}{FN}, 
             $tether_info{METHOD}{$method_name}{FP}, 
             $tether_info{METHOD}{$method_name}{TN}
            );


        #####
        ## output
        print FH_PR join(", ", ($this_threshold, 
            $tether_info{METHOD}{$method_name}{TP}, 
            $tether_info{METHOD}{$method_name}{FN}, 
            $tether_info{METHOD}{$method_name}{FP}, 
            $tether_info{METHOD}{$method_name}{TN},
            $tether_info{METHOD}{$method_name}{PRECISION},
            $tether_info{METHOD}{$method_name}{RECALL}))."\n";
    }

    close FH_PR;
}



##############################################################################
## d) RTT (variance): RTT_variance.threshold<threshold>.<file id>.txt
##                    Thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, .. , 0.8);
my @rtt_thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8);

my $rtt_output_file = "RTT_variance.PR.$file_id.txt";
open FH_PR, "> $output_dir/$rtt_output_file" or die $!;

foreach my $this_threshold (@rtt_thresholds) {
    $method_name = "RTT_variance.threshold$this_threshold";
    $file_name = "$method_name.$file_id.txt";


    #####
    ## read in data
    open FH, "$input_dir/$file_name" or die $!;
    while(my $this_ip = <FH>) {
        chomp $this_ip;
        print $this_ip."\n" if($DEBUG1);


        ## DEBUG
        die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

        $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
    }
    close FH;


    #####
    ## statistics
    (
     $tether_info{METHOD}{$method_name}{TP}, 
     $tether_info{METHOD}{$method_name}{FN}, 
     $tether_info{METHOD}{$method_name}{FP}, 
     $tether_info{METHOD}{$method_name}{TN}
    ) = cal_confusion_matrix($based_method, $method_name, \%tether_info);

    $tether_info{METHOD}{$method_name}{PRECISION} = MyUtil::precision(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );
    $tether_info{METHOD}{$method_name}{RECALL} = MyUtil::recall(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );


    #####
    ## output
    print FH_PR join(", ", ($this_threshold, 
        $tether_info{METHOD}{$method_name}{TP}, 
        $tether_info{METHOD}{$method_name}{FN}, 
        $tether_info{METHOD}{$method_name}{FP}, 
        $tether_info{METHOD}{$method_name}{TN},
        $tether_info{METHOD}{$method_name}{PRECISION},
        $tether_info{METHOD}{$method_name}{RECALL}))."\n";
}
close FH_PR;


##############################################################################
## e) Inter-arrival time (mean) : Inter_arrival_time_mean.threshold<threshold>.<file id>.txt
##                                Thresholds = (0.005, 0.01, 0.02, 0.03, 0.05, .. , 4)
my @thresholds = (0.005, 0.01, 0.02, 0.03, 0.05, 0.07, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 3, 4);

my $output_file = "Inter_arrival_time_mean.PR.$file_id.txt";
open FH_PR, "> $output_dir/$output_file" or die $!;

foreach my $this_threshold (@thresholds) {
    $method_name = "Inter_arrival_time_mean.threshold$this_threshold";
    $file_name = "$method_name.$file_id.txt";


    #####
    ## read in data
    open FH, "$input_dir/$file_name" or die $!;
    while(my $this_ip = <FH>) {
        chomp $this_ip;
        print $this_ip."\n" if($DEBUG1);


        ## DEBUG
        die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

        $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
    }
    close FH;


    #####
    ## statistics
    (
     $tether_info{METHOD}{$method_name}{TP}, 
     $tether_info{METHOD}{$method_name}{FN}, 
     $tether_info{METHOD}{$method_name}{FP}, 
     $tether_info{METHOD}{$method_name}{TN}
    ) = cal_confusion_matrix($based_method, $method_name, \%tether_info);

    $tether_info{METHOD}{$method_name}{PRECISION} = MyUtil::precision(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );
    $tether_info{METHOD}{$method_name}{RECALL} = MyUtil::recall(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );


    #####
    ## output
    print FH_PR join(", ", ($this_threshold, 
        $tether_info{METHOD}{$method_name}{TP}, 
        $tether_info{METHOD}{$method_name}{FN}, 
        $tether_info{METHOD}{$method_name}{FP}, 
        $tether_info{METHOD}{$method_name}{TN},
        $tether_info{METHOD}{$method_name}{PRECISION},
        $tether_info{METHOD}{$method_name}{RECALL}))."\n";
}
close FH_PR;


##############################################################################
## f) Inter-arrival time (stdev): Inter_arrival_time_stdev.threshold<threshold>.<file id>.txt
##                                Thresholds = (0.005, 0.01, 0.15, 0.2, 0.25, .. , 10)
@thresholds = (0.005, 0.01, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5, 5.5, 6, 6.5, 7, 8, 9, 10);

$output_file = "Inter_arrival_time_stdev.PR.$file_id.txt";
open FH_PR, "> $output_dir/$output_file" or die $!;

foreach my $this_threshold (@thresholds) {
    $method_name = "Inter_arrival_time_stdev.threshold$this_threshold";
    $file_name = "$method_name.$file_id.txt";


    #####
    ## read in data
    open FH, "$input_dir/$file_name" or die $!;
    while(my $this_ip = <FH>) {
        chomp $this_ip;
        print $this_ip."\n" if($DEBUG1);


        ## DEBUG
        die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

        $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
    }
    close FH;


    #####
    ## statistics
    (
     $tether_info{METHOD}{$method_name}{TP}, 
     $tether_info{METHOD}{$method_name}{FN}, 
     $tether_info{METHOD}{$method_name}{FP}, 
     $tether_info{METHOD}{$method_name}{TN}
    ) = cal_confusion_matrix($based_method, $method_name, \%tether_info);

    $tether_info{METHOD}{$method_name}{PRECISION} = MyUtil::precision(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );
    $tether_info{METHOD}{$method_name}{RECALL} = MyUtil::recall(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );


    #####
    ## output
    print FH_PR join(", ", ($this_threshold, 
        $tether_info{METHOD}{$method_name}{TP}, 
        $tether_info{METHOD}{$method_name}{FN}, 
        $tether_info{METHOD}{$method_name}{FP}, 
        $tether_info{METHOD}{$method_name}{TN},
        $tether_info{METHOD}{$method_name}{PRECISION},
        $tether_info{METHOD}{$method_name}{RECALL}))."\n";
}
close FH_PR;


##############################################################################
## g) Throughput : Tput_whole_trace.threshold<threshold>.<file id>.txt
##                 Thresholds = (10, 15, 20, 25, 30, 40, 50, 60, .. , 10000)
@thresholds = (10, 15, 20, 25, 30, 40, 50, 60, 70, 80, 90, 100, 120, 140, 160, 180, 200, 250, 300, 400, 500, 600, 700, 800, 900, 1000, 1500, 2000, 3000, 5000, 10000);

$output_file = "Tput_whole_trace.PR.$file_id.txt";
open FH_PR, "> $output_dir/$output_file" or die $!;

foreach my $this_threshold (@thresholds) {
    $method_name = "Tput_whole_trace.threshold$this_threshold";
    $file_name = "$method_name.$file_id.txt";


    #####
    ## read in data
    open FH, "$input_dir/$file_name" or die $!;
    while(my $this_ip = <FH>) {
        chomp $this_ip;
        print $this_ip."\n" if($DEBUG1);


        ## DEBUG
        die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

        $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
    }
    close FH;


    #####
    ## statistics
    (
     $tether_info{METHOD}{$method_name}{TP}, 
     $tether_info{METHOD}{$method_name}{FN}, 
     $tether_info{METHOD}{$method_name}{FP}, 
     $tether_info{METHOD}{$method_name}{TN}
    ) = cal_confusion_matrix($based_method, $method_name, \%tether_info);

    $tether_info{METHOD}{$method_name}{PRECISION} = MyUtil::precision(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );
    $tether_info{METHOD}{$method_name}{RECALL} = MyUtil::recall(
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        );


    #####
    ## output
    print FH_PR join(", ", ($this_threshold, 
        $tether_info{METHOD}{$method_name}{TP}, 
        $tether_info{METHOD}{$method_name}{FN}, 
        $tether_info{METHOD}{$method_name}{FP}, 
        $tether_info{METHOD}{$method_name}{TN},
        $tether_info{METHOD}{$method_name}{PRECISION},
        $tether_info{METHOD}{$method_name}{RECALL}))."\n";
}
close FH_PR;


##############################################################################
## h) Pkt length Entropy : Pkt_len_entropy.timebin<time bin size>.threshold<threshold>.<file id>.txt
##                         Time bins  = (1, 600)
##                         Thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, .. , 2)
my @time_bins = (1, 600);
@thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, 0.035, 0.04, 0.045, 0.05, 0.055, 0.06, 0.07, 0.08, 0.09, 0.1, 0.15, 0.2, 0.25, 0.3, 0.5, 0.7, 0.9, 1, 1.2, 1.4, 1.6, 1.8, 2);
foreach my $this_timebin (@time_bins) {
    my $output_file = "Pkt_len_entropy.timebin$this_timebin.PR.$file_id.txt";
    open FH_PR, "> $output_dir/$output_file" or die $!;

    foreach my $this_threshold (@thresholds) {
        $method_name = "Pkt_len_entropy.timebin$this_timebin.threshold$this_threshold";
        $file_name = "$method_name.$file_id.txt";
        

        #####
        ## read in data
        open FH, "$input_dir/$file_name" or die $!;
        while(my $this_ip = <FH>) {
            chomp $this_ip;
            print $this_ip."\n" if($DEBUG1);


            ## DEBUG
            die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

            $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
        }
        close FH;


        #####
        ## statistics
        (
         $tether_info{METHOD}{$method_name}{TP}, 
         $tether_info{METHOD}{$method_name}{FN}, 
         $tether_info{METHOD}{$method_name}{FP}, 
         $tether_info{METHOD}{$method_name}{TN}
        ) = cal_confusion_matrix($based_method, $method_name, \%tether_info);

        $tether_info{METHOD}{$method_name}{PRECISION} = MyUtil::precision(
             $tether_info{METHOD}{$method_name}{TP}, 
             $tether_info{METHOD}{$method_name}{FN}, 
             $tether_info{METHOD}{$method_name}{FP}, 
             $tether_info{METHOD}{$method_name}{TN}
            );
        $tether_info{METHOD}{$method_name}{RECALL} = MyUtil::recall(
             $tether_info{METHOD}{$method_name}{TP}, 
             $tether_info{METHOD}{$method_name}{FN}, 
             $tether_info{METHOD}{$method_name}{FP}, 
             $tether_info{METHOD}{$method_name}{TN}
            );


        #####
        ## output
        print FH_PR join(", ", ($this_threshold, 
            $tether_info{METHOD}{$method_name}{TP}, 
            $tether_info{METHOD}{$method_name}{FN}, 
            $tether_info{METHOD}{$method_name}{FP}, 
            $tether_info{METHOD}{$method_name}{TN},
            $tether_info{METHOD}{$method_name}{PRECISION},
            $tether_info{METHOD}{$method_name}{RECALL}))."\n";
    }

    close FH_PR;
}




###########################################
## plot the figures
system("sed 's/FILE_ID/$file_id/;' plot_pr.plot.mother > plot_pr.plot");
system("gnuplot plot_pr.plot");
system("rm plot_pr.plot");

1;


#####
## Functions

sub cal_confusion_matrix {
    my ($ground_method, $test_method, $ref_info) = @_;
    my $tp = 0;
    my $fp = 0;
    my $tn = 0;
    my $fn = 0;

    foreach my $this_ip (keys %{ $ref_info->{IP} }) {
        print $this_ip.": " if($DEBUG1);

        my $detected_by_ground_method = 0;
        my $detected_by_test_method = 0;
        foreach my $this_method (keys %{ $ref_info->{IP}{$this_ip}{METHOD} }) {
            print $this_method.", " if($DEBUG1);


            if($this_method eq $ground_method) {
                $detected_by_ground_method = 1;
            }
            elsif($this_method eq $test_method) {
                $detected_by_test_method = 1;
            }
        }

        print "\n" if($DEBUG1);


        if($detected_by_ground_method == 1 and $detected_by_test_method == 1) {
            print "  => TP\n" if($DEBUG1);
            $tp ++;
        }
        elsif($detected_by_ground_method == 1 and $detected_by_test_method == 0) {
            print "  => FN\n" if($DEBUG1);
            $fn ++;
        }
        elsif($detected_by_ground_method == 0 and $detected_by_test_method == 1) {
            print "  => FP\n" if($DEBUG1);
            $fp ++;
        }
        elsif($detected_by_ground_method == 0 and $detected_by_test_method == 0) {
            print "  => TN\n" if($DEBUG1);
            $tn ++;
        }
    }

    return ($tp, $fn, $fp, $tn);
}



