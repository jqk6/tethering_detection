#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/24 @ Narus 
##
## Read in results from "analyze_sprint_udp_connections.pl" and detect tethering using number of connections.
## e.g. > n connections at any time using time bin size b
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_udp_connections.pl", i.e.
##     ./output/
##     a) file.<id>.udp_connections.bin<time bin size>.txt
##          timeseries of # of connections
##
## - output:
##      IP of tethered clients.
##          ./tethered_clients/UDP_Connections_timebin<time bin size>.threshold<threshold>.<file id>.txt
##
##  e.g.
##      perl detect_tethering_udp_connections.pl 49
##
##################################################


use strict;


#####
## constant
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug



#####
## variables
my $input_dir = "./output";
my $output_dir = "./tethered_clients";

my $file_id;

my %ip_info;        ## to store the information of each IP
                    ## {$timebin_size}{IP}{$src}{connections}{@connections}
                    ## @{$timebin_size}{threshold}{$threshold}{$tethered_ips}
my @timebins = (1, 5, 10, 60, 600); ## the time bin size we want to analyze
my @thresholds = (2 .. 30);

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

#######################################
## readin IP info:
##
##  connections
foreach my $this_timebin (@timebins) {
    my $file_name = "file.$file_id.udp_connections.bin$this_timebin.txt";
    open FH, "$input_dir/$file_name" or die $!."\n$file_name\n";
    while(<FH>) {
        my ($src, @connections) = split(/, /, $_);
        pop(@connections);
        ## convert to numbers
        for (0 .. scalar(@connections)-1) {
            $connections[$_] += 0;
        }
        

        print "$src has ".join(",", @connections)."\n" if($DEBUG2);

        @{ $ip_info{$this_timebin}{IP}{$src}{connections} } = @connections;
    }
    close FH;    
}
## end readin IP info
#######################################


#####
## find tethering using # of connections
foreach my $this_timebin (@timebins) {
    foreach my $this_threshold (@thresholds) {
        foreach my $this_src (keys %{ $ip_info{$this_timebin}{IP} }) {
            foreach my $this_conn_cnt (@{ $ip_info{$this_timebin}{IP}{$this_src}{connections} }) {
                if($this_conn_cnt > $this_threshold) {
                    ## tethering detected 
                    $ip_info{$this_timebin}{$this_threshold}{$this_src} = 1;
                    last;
                }
            }
        }
    }
}

#####
## output

foreach my $this_timebin (@timebins) {
    foreach my $this_threshold (@thresholds) {
        my $file_output = "UDP_Connections_timebin$this_timebin.threshold$this_threshold.$file_id.txt";
        open FH, "> $output_dir/$file_output" or die $!;
        foreach my $this_src (keys %{ $ip_info{$this_timebin}{$this_threshold} }) {
            print FH $this_src."\n";
        }
        close FH;
    }
}

1;



#####
## functions
