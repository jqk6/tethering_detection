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
##      Possible base:
##      a) TTL (whole trace)         : TTL_whole_trace.<file id>.txt
##      b) TTL (one second)          : TTL_one_second.<file id>.txt
##      c) TTL (default value)       : TTL_default_value.<file id>.txt
##      d) User Agent                : User_agent.<file id>.txt
##      e) TTL (diff)                : TTL_diff.<file id>.txt
##
##      Evaluation Methods
##      a) Connections               : Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 5, 10, 60, 600)
##                                     Thresholds = (2 .. 30)
##      b) RTT (variance)            : RTT_variance.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, .. , 0.8)
##      c) Inter-arrival time (mean) : Inter_arrival_time_mean.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.005, 0.01, 0.02, 0.03, 0.05, .. , 4)
##      d) Inter-arrival time (stdev): Inter_arrival_time_stdev.threshold<threshold>.<file id>.txt
##                                     Thresholds = (0.005, 0.01, 0.15, 0.2, 0.25, .. , 10)
##      e) Throughput                : Tput_whole_trace.threshold<threshold>.<file id>.txt
##                                     Thresholds = (10, 15, 20, 25, 30, 40, 50, 60, .. , 10000)
##      f) Pkt length Entropy        : Pkt_len_entropy.timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 600)
##                                     Thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, .. , 2)
##      g) UDP Connections           : UDP_Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 5, 10, 60, 600)
##                                     Thresholds = (2 .. 30)
##      h) TCP/UDP Connections       : TCP_UDP_Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                                     Time bins  = (1, 5, 10, 60, 600)
##                                     Thresholds = (2 .. 30)
##      i) Boot Time                 : boot_time.method_<methods>.<parameters>.DIFF_<time diff>.NUM_<num pkt>.<file id>.txt
##                                     Frequency estimation methods: (1, 2, 3)
##                                          1 = WINDOW based
##                                          2 = EWMA based
##                                          3 = last calculated freq
##                                     Frequency estimation parameters: 
##                                          1: (10, 100)
##                                          2: (0.5, 0.9)
##                                          3: (1)
##                                     THRESHOLD_EST_RX_DIFF = (1 5 30 120)
##                                     OUT_RANGE_NUM = (1 5 10)
##
## - output:
##      PR curve (Precision-Recall)
##      1) raw data:
##        ./tethered_clients_processed_data/
##        format:
##        <threshold> <TP> <FN> <FP> <TN> <precision> <recall>
##      2) figures:
##        ./tethered_clients_figures/
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

my $PLOT_a = 0;
my $PLOT_b = 0;
my $PLOT_c = 0;
my $PLOT_d = 0;
my $PLOT_e = 0;
my $PLOT_f = 0;
my $PLOT_g = 0;
my $PLOT_h = 0;
my $PLOT_i = 1;


my $FILTERED_SRC_IP = 1;    ## in the trace, some packets are from clients and some are from servers
                            ## we are not interested in those from servers
                            ## it seems the clients from cellular network (Sprint) have IP: 28.XXX.XXX.XXX


#####
## variables
my $input_dir = "./tethered_clients";
my $input_all_client_dir = "./output";
my $output_dir = "./tethered_clients_processed_data";
my @base_methods = ("TTL_one_second", "TTL_whole_trace", "TTL_default_value", "TTL_diff", "User_agent");


my $file_id;

my %tether_info;        ## to store the information of tethered IP
                        ## {IP}{ip}{METHOD}{methods}
                        ## {METHOD}{method}{TP}{tp}
                        ## {METHOD}{method}{FN}{fn}
                        ## {METHOD}{method}{FP}{fp}
                        ## {METHOD}{method}{TN}{tn}
                        ## {METHOD}{method}{PRECISION}{precision}
                        ## {METHOD}{method}{RECALL}{recall}
my @thresholds;


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
    
    if($FILTERED_SRC_IP == 1) {
        next if(!($ip =~ /^28\./));
    }

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
print "detected IPs of each method\n" if($DEBUG2);
## a) TTL (whole trace): TTL_whole_trace.<file id>.txt
## b) TTL (one second) : TTL_one_second.<file id>.txt
## c) TTL (default value) : TTL_default_value.<file id>.txt
## d) User Agent : User_agent.<file id>.txt
## e) TTL (diff): TTL_diff.<file id>.txt
foreach my $method_name (@base_methods) {
    $file_name = "$method_name.$file_id.txt";
    open FH, "$input_dir/$file_name" or die $!;
    while(my $this_ip = <FH>) {
        chomp $this_ip;
        print $this_ip."\n" if($DEBUG1);

        if($FILTERED_SRC_IP == 1) {
            next if(!($this_ip =~ /^28\./));
        }


        ## DEBUG
        die "no such IP: $this_ip\n" if(!(exists $tether_info{IP}{$this_ip}));

        $tether_info{IP}{$this_ip}{METHOD}{$method_name} = 1;
    }
    close FH;
}



##############################################################################
## a) Connections: Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                 Time bins  = (1, 5, 10, 60, 600)
##                 Thresholds = (2 .. 30)
if($PLOT_a) {
    print "a) Connections\n" if($DEBUG2);

    my @conntions_time_bins = (1, 5, 10, 60, 600);
    my @connections_thresholds = (2 .. 30);

    foreach my $based_method (@base_methods) {

        foreach my $this_timebin (@conntions_time_bins) {
            my $conn_output_file = "Connections_timebin$this_timebin.base_$based_method.PR.$file_id.txt";
            open FH_PR, "> $output_dir/$conn_output_file" or die $!;

            foreach my $this_threshold (@connections_thresholds) {
                my $method_name = "Connections_timebin$this_timebin.threshold$this_threshold";
                $file_name = "$method_name.$file_id.txt";
                

                #####
                ## read in data
                open FH, "$input_dir/$file_name" or die $!;
                while(my $this_ip = <FH>) {
                    chomp $this_ip;
                    print $this_ip."\n" if($DEBUG1);

                    if($FILTERED_SRC_IP == 1) {
                        next if(!($this_ip =~ /^28\./));
                    }


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
    }

}



##############################################################################
## b) RTT (variance): RTT_variance.threshold<threshold>.<file id>.txt
##                    Thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, .. , 0.8);
if($PLOT_b) {
    print "b) RTT (variance)\n" if($DEBUG2);
    my @rtt_thresholds = (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8);

    foreach my $based_method (@base_methods) {

        my $rtt_output_file = "RTT_variance.base_$based_method.PR.$file_id.txt";
        open FH_PR, "> $output_dir/$rtt_output_file" or die $!;

        foreach my $this_threshold (@rtt_thresholds) {
            my $method_name = "RTT_variance.threshold$this_threshold";
            $file_name = "$method_name.$file_id.txt";


            #####
            ## read in data
            open FH, "$input_dir/$file_name" or die $!;
            while(my $this_ip = <FH>) {
                chomp $this_ip;
                print $this_ip."\n" if($DEBUG1);

                if($FILTERED_SRC_IP == 1) {
                    next if(!($this_ip =~ /^28\./));
                }


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
}


##############################################################################
## c) Inter-arrival time (mean) : Inter_arrival_time_mean.threshold<threshold>.<file id>.txt
##                                Thresholds = (0.005, 0.01, 0.02, 0.03, 0.05, .. , 4)
if($PLOT_c) {
    print "c) Inter-arrival time (mean) \n" if($DEBUG2);

    my @thresholds = (0.005, 0.01, 0.02, 0.03, 0.05, 0.07, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 3, 4);

    foreach my $based_method (@base_methods) {
        my $output_file = "Inter_arrival_time_mean.base_$based_method.PR.$file_id.txt";
        open FH_PR, "> $output_dir/$output_file" or die $!;

        foreach my $this_threshold (@thresholds) {
            my $method_name = "Inter_arrival_time_mean.threshold$this_threshold";
            $file_name = "$method_name.$file_id.txt";


            #####
            ## read in data
            open FH, "$input_dir/$file_name" or die $!;
            while(my $this_ip = <FH>) {
                chomp $this_ip;
                print $this_ip."\n" if($DEBUG1);

                if($FILTERED_SRC_IP == 1) {
                    next if(!($this_ip =~ /^28\./));
                }


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
}


##############################################################################
## d) Inter-arrival time (stdev): Inter_arrival_time_stdev.threshold<threshold>.<file id>.txt
##                                Thresholds = (0.005, 0.01, 0.15, 0.2, 0.25, .. , 10)
if($PLOT_d) {
    print "d) Inter-arrival time (stdev)\n" if($DEBUG2);

    @thresholds = (0.005, 0.01, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5, 5.5, 6, 6.5, 7, 8, 9, 10);

    foreach my $based_method (@base_methods) {
        my $output_file = "Inter_arrival_time_stdev.base_$based_method.PR.$file_id.txt";
        open FH_PR, "> $output_dir/$output_file" or die $!;

        foreach my $this_threshold (@thresholds) {
            my $method_name = "Inter_arrival_time_stdev.threshold$this_threshold";
            $file_name = "$method_name.$file_id.txt";


            #####
            ## read in data
            open FH, "$input_dir/$file_name" or die $!;
            while(my $this_ip = <FH>) {
                chomp $this_ip;
                print $this_ip."\n" if($DEBUG1);

                if($FILTERED_SRC_IP == 1) {
                    next if(!($this_ip =~ /^28\./));
                }


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
}


##############################################################################
## e) Throughput : Tput_whole_trace.threshold<threshold>.<file id>.txt
##                 Thresholds = (10, 15, 20, 25, 30, 40, 50, 60, .. , 10000)
if($PLOT_e) {
    print "e) Throughput\n" if($DEBUG2);

    @thresholds = (10, 15, 20, 25, 30, 40, 50, 60, 70, 80, 90, 100, 120, 140, 160, 180, 200, 250, 300, 400, 500, 600, 700, 800, 900, 1000, 1500, 2000, 3000, 5000, 10000);

    foreach my $based_method (@base_methods) {
        my $output_file = "Tput_whole_trace.base_$based_method.PR.$file_id.txt";
        open FH_PR, "> $output_dir/$output_file" or die $!;

        foreach my $this_threshold (@thresholds) {
            my $method_name = "Tput_whole_trace.threshold$this_threshold";
            $file_name = "$method_name.$file_id.txt";


            #####
            ## read in data
            open FH, "$input_dir/$file_name" or die $!;
            while(my $this_ip = <FH>) {
                chomp $this_ip;
                print $this_ip."\n" if($DEBUG1);

                if($FILTERED_SRC_IP == 1) {
                    next if(!($this_ip =~ /^28\./));
                }


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
}


##############################################################################
## f) Pkt length Entropy : Pkt_len_entropy.timebin<time bin size>.threshold<threshold>.<file id>.txt
##                         Time bins  = (1, 600)
##                         Thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, .. , 2)
if($PLOT_f) {
    print "f) Pkt length Entropy\n" if($DEBUG2);

    my @time_bins = (1, 600);
    @thresholds = (0.01, 0.015, 0.02, 0.025, 0.03, 0.035, 0.04, 0.045, 0.05, 0.055, 0.06, 0.07, 0.08, 0.09, 0.1, 0.15, 0.2, 0.25, 0.3, 0.5, 0.7, 0.9, 1, 1.2, 1.4, 1.6, 1.8, 2);

    foreach my $based_method (@base_methods) {
        foreach my $this_timebin (@time_bins) {
            my $output_file = "Pkt_len_entropy.timebin$this_timebin.base_$based_method.PR.$file_id.txt";
            open FH_PR, "> $output_dir/$output_file" or die $!;

            foreach my $this_threshold (@thresholds) {
                my $method_name = "Pkt_len_entropy.timebin$this_timebin.threshold$this_threshold";
                $file_name = "$method_name.$file_id.txt";
                

                #####
                ## read in data
                open FH, "$input_dir/$file_name" or die $!;
                while(my $this_ip = <FH>) {
                    chomp $this_ip;
                    print $this_ip."\n" if($DEBUG1);

                    if($FILTERED_SRC_IP == 1) {
                        next if(!($this_ip =~ /^28\./));
                    }


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
    }
}


##############################################################################
## g) UDP Connections: UDP_Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                     Time bins  = (1, 5, 10, 60, 600)
##                     Thresholds = (2 .. 30)
# @conntions_time_bins and @connections_thresholds are the same as TCP Connections
if($PLOT_g) {
    print "g) UDP Connections\n" if($DEBUG2);

    my @conntions_time_bins = (1, 5, 10, 60, 600);
    my @connections_thresholds = (2 .. 30);

    foreach my $based_method (@base_methods) {
        foreach my $this_timebin (@conntions_time_bins) {
            my $conn_output_file = "UDP_Connections_timebin$this_timebin.base_$based_method.PR.$file_id.txt";
            open FH_PR, "> $output_dir/$conn_output_file" or die $!;

            foreach my $this_threshold (@connections_thresholds) {
                my $method_name = "UDP_Connections_timebin$this_timebin.threshold$this_threshold";
                $file_name = "$method_name.$file_id.txt";
                

                #####
                ## read in data
                open FH, "$input_dir/$file_name" or die $!;
                while(my $this_ip = <FH>) {
                    chomp $this_ip;
                    print $this_ip."\n" if($DEBUG1);

                    if($FILTERED_SRC_IP == 1) {
                        next if(!($this_ip =~ /^28\./));
                    }


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
    }
}



##############################################################################
## h) TCP/UDP Connections: TCP_UDP_Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##                     Time bins  = (1, 5, 10, 60, 600)
##                     Thresholds = (2 .. 30)
# @conntions_time_bins and @connections_thresholds are the same as TCP Connections
if($PLOT_h) {

    print "h) TCP/UDP Connections\n" if($DEBUG2);

    my @conntions_time_bins = (1, 5, 10, 60, 600);
    my @connections_thresholds = (2 .. 30);
    
    foreach my $based_method (@base_methods) {
        foreach my $this_timebin (@conntions_time_bins) {
            my $conn_output_file = "TCP_UDP_Connections_timebin$this_timebin.base_$based_method.PR.$file_id.txt";
            open FH_PR, "> $output_dir/$conn_output_file" or die $!;

            foreach my $this_threshold (@connections_thresholds) {
                my $method_name = "TCP_UDP_Connections_timebin$this_timebin.threshold$this_threshold";
                $file_name = "$method_name.$file_id.txt";
                

                #####
                ## read in data
                open FH, "$input_dir/$file_name" or die $!;
                while(my $this_ip = <FH>) {
                    chomp $this_ip;
                    print $this_ip."\n" if($DEBUG1);

                    if($FILTERED_SRC_IP == 1) {
                        next if(!($this_ip =~ /^28\./));
                    }


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
    }
}



##############################################################################
## i) Boot Time: boot_time.method_<methods>.<parameters>.DIFF_<time diff>.NUM_<num pkt>.<file id>.txt
##              Frequency estimation methods: (1, 2, 3)
##                   1 = WINDOW based
##                   2 = EWMA based
##                   3 = last calculated freq
##              Frequency estimation parameters: 
##                   1: (10, 100)
##                   2: (0.5, 0.9)
##                   3: (1)
##              THRESHOLD_EST_RX_DIFF = (1 5 30 120)
##              OUT_RANGE_NUM = (1 5 10)
if($PLOT_i) {
    print "i) Boot time\n" if($DEBUG2);

    my @boot_time_methods = (1 .. 3);
    my @boot_time_params  = ([10, 100], [0.5, 0.9], [1]);
    my @boot_time_diff    = (1, 5, 30, 120);
    my @boot_time_num     = (1, 5, 10);

    foreach my $based_method (@base_methods) {

        my $boot_time_output_file = "boot_time.base_$based_method.PR.$file_id.txt";
        open FH_PR, "> $output_dir/$boot_time_output_file" or die $!;
        foreach my $this_freq_method (@boot_time_methods) {
            foreach my $this_param (@{$boot_time_params[$this_freq_method-1]}) {
                foreach my $this_diff (@boot_time_diff) {
                    foreach my $this_num (@boot_time_num) {
                        print "$this_freq_method-$this_param-$this_diff-$this_num\n" if($DEBUG1);


                        my $method_name = "boot_time.method_$this_freq_method.$this_param.DIFF_$this_diff.NUM_$this_num";
                        $file_name = "$method_name.$file_id.txt";


                        #####
                        ## read in data
                        open FH, "$input_dir/$file_name" or die $!."$input_dir/$file_name\n";
                        while(my $this_ip = <FH>) {
                            chomp $this_ip;
                            print $this_ip."\n" if($DEBUG1);

                            if($FILTERED_SRC_IP == 1) {
                                next if(!($this_ip =~ /^28\./));
                            }


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
                        print FH_PR join(", ", ("$this_freq_method-$this_param-$this_diff-$this_num", 
                            $tether_info{METHOD}{$method_name}{TP}, 
                            $tether_info{METHOD}{$method_name}{FN}, 
                            $tether_info{METHOD}{$method_name}{FP}, 
                            $tether_info{METHOD}{$method_name}{TN},
                            $tether_info{METHOD}{$method_name}{PRECISION},
                            $tether_info{METHOD}{$method_name}{RECALL}))."\n";
                    }
                }
            }
        }
        close FH_PR;
    }
}




###########################################
## plot the figures
foreach my $based_method (@base_methods) {
    system("sed 's/FILE_ID/$file_id/;s/BASE_METHOD/$based_method/' plot_pr.plot.mother > plot_pr.plot");
    system("gnuplot plot_pr.plot");
    system("rm plot_pr.plot");
}

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



