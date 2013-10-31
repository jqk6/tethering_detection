#!/bin/perl

##################################################
## Author: Yi-Chao Chen
## 2013/08/19 @ Narus
##
## modified from calculate_clock_skew_sue.pl. Take its output and calculate the clock skew of smaller segments.
##
## - input: 
##   a) ./output/file.<ip>.offset.txt:
##      <tx_time> <rx_time> <rx_time_from_1st_pkt> <tx_clock_from_1st_pkt> <tx_time_from_1st_pkt> <offset>
##   b) segment size
##
## - output
##     a) <skew of the entire trace> <avg skew of segments> <stdev skew of segments>
##     b) ./output/<file name>.seg.skew.txt
##
## - internal variables
##     a) PLOT_EPS : output eps or png figure
##     c) gnuplot  : modify to choose which IPs to plot
##
##  e.g.
##      perl calculate_clock_skew_sue_segment.pl 2013.08.19.40utmachines.pcap.txt.128.83.144.188.offset.txt 60
##################################################

use strict;

use ClockSkewMoon;
use MyUtil;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 0; ## print for debug

my $FIX_UT_FREQ      = 1; ## fix the clock frequency of UT machines to 250Hz
my $FIX_HTC_FREQ     = 1; ## fix the clock frequency of HTC One X to 100Hz
my $FIX_SAMSUNG_FREQ = 1; ## fix the clock frequency of Samsung Tablet to 128Hz
my $FIX_IPHONE_FREQ  = 1; ## fix the clock frequency of iPhone to 1000Hz
my $FIX_IAD_FREQ     = 1; ## fix the clock frequency of iPhone to 1000Hz
my $FIX_MAC_FREQ     = 1; ## fix the clock frequency of MacBook to 1000Hz
my $FIX_OTHER_FREQ   = 1; ## fix the clock frequency of oher machines ...

# my $FIX_DEST         = 1; ## 1 to fix the TCP destination (necessary if there are more than 1 TCP connection)
# my $FIX_DEST_ADDR    = "192.168.5.67";
# my $FIX_DEST_ADDR    = "199.116.177.167";
# my $FIX_DEST_ADDR    = "10.0.2.1";
# my $FIX_DEST_ADDR    = "69.171.237.20";
# my $FIX_DEST_ADDR    = "64.185.182.185";
# my $FIX_DEST_ADDR    = "128.83.40.144";
# my $FIX_DEST_ADDR    = "128.83.120.139";
# my $FIX_DEST_ADDR    = "128.83.141.71";
# my $FIX_DEST_ADDR    = "192.168.1.3";


my $PLOT_EPS         = 0; ## 1 to output eps; 0 to output png figure
# my $PLOT_IP          = "192.168.4.78";
# my $PLOT_IP          = "10.0.2.4";
# my $PLOT_IP          = "10.0.2.5";
# my $PLOT_IP          = "10.0.2.8";
my $PLOT_IP          = "128.83";


#####
## variables
my $output_dir = "./output";
my $figure_dir = "./figures";
my $gnuplot_file = "plot_skew.plot";


my $file_name;

my @offset;
my @rx_interval;

my @freq_candidates = (100, 250, 1000);  ## choose the clock frequency as the closest one
# my @freq_candidates = ();
my $freq_threshold = 0.4;           ## the threshold if close to one of the above frequency
my $threshold = 50;                ## only calculate IPs with enough TCP packets
my $seg_size = 60;                  ## seconds per segment

#####
## check input
if(@ARGV != 2) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
$seg_size = $ARGV[1] + 0;
my @tmp = split(/\//, $file_name);
my $pure_name = pop(@tmp);
print "input file = $file_name\n" if($DEBUG1);
print "input file name = $pure_name\n" if($DEBUG2);


#####
## main starts here
print STDERR "start to read data..\n" if($DEBUG2);
open FH, "$file_name" or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file

    ## format
    ##   <tx_time> <rx_time> <rx_time_from_1st_pkt> <tx_clock_from_1st_pkt> <tx_time_from_1st_pkt> <offset>
    my ($tx_time, $rx_time, $rx_time_from_1st_pkt, $tx_clock_from_1st_pkt, $tx_time_from_1st_pkt, $offset) = split(/,/, $_);
    $tx_time += 0; $rx_time += 0; $rx_time_from_1st_pkt += 0; $tx_clock_from_1st_pkt += 0; $tx_time_from_1st_pkt += 0; $offset += 0;

    print join(",", ($tx_time, $rx_time, $rx_time_from_1st_pkt, $tx_clock_from_1st_pkt, $tx_time_from_1st_pkt, $offset))."\n" if($DEBUG1);

    push(@offset, $offset);
    push(@rx_interval, $rx_time_from_1st_pkt);
    
}
close FH;

print "size=".scalar(@offset)."\n" if($DEBUG1);
my @skew = ();
# foreach my $si (0 .. scalar(@offset)-$seg_size-1) {
#     my $ei = $si + $seg_size - 1;
#     my @tmp_offset = @offset[$si .. $ei];
#     my @tmp_rx_interval = @rx_interval[$si .. $ei];
#     my ($alpha, $beta) = ClockSkewMoon::clock_skew_moon(\@tmp_offset, \@tmp_rx_interval);
#     push(@skew, $alpha);
# }
my $si = 0;
while ($si < scalar(@offset)) {
    my $s_rx = $rx_interval[$si];

    my $ei = $si + 1;
    my $e_rx = -1;
    while ($ei < scalar(@offset)) {
        $e_rx = $rx_interval[$ei];

        last if( ($e_rx - $s_rx) > $seg_size);

        $ei += 2;
    }

    if( ($e_rx - $s_rx) > $seg_size) {
        print "$s_rx ($si) - $e_rx ($ei)\n" if($DEBUG1);

        my @tmp_offset = @offset[$si .. $ei];
        my @tmp_rx_interval = @rx_interval[$si .. $ei];
        my ($alpha, $beta) = ClockSkewMoon::clock_skew_moon(\@tmp_offset, \@tmp_rx_interval);
        $alpha *= 1000000;
        push(@skew, $alpha);

        $si = $ei;
    }
    else {
        last;
    }
}
my ($alpha, $beta) = ClockSkewMoon::clock_skew_moon(\@offset, \@rx_interval);
$alpha *= 1000000;
print "$alpha, ".MyUtil::average(\@skew).", ".MyUtil::stdev(\@skew)."\n";

open FH, "> $output_dir/$pure_name.seg.skew.txt" or die $!;
print FH "".join("\n", @skew);
close FH;

