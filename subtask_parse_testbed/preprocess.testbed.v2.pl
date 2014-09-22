#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2014.04.14 @ UT Austin
##
## filter out:
## - pkts: reordering of Timestamp
## - pkts: UDP
## - flow w/o enough packets
## - flow too short
## - flow w/ multiple TTLs
## - flow w/o monotonic TS
## - IP w/o enough packets
## - IP w/o UA
## - IP w/o same freq
## - IP w/o same boot time
##
## filter out packets which is:
##
## - input:
##
## - output:
##
## - e.g.
##    perl preprocess.testbed.v2.pl exp1
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use lib "../utils";

use Tethering;


#############
# Debug
#############
my $DEBUG0 = 0;
my $DEBUG1 = 1;
my $DEBUG2 = 1; ## print progress
my $DEBUG3 = 1; ## print output

my $NUM_PKT_PER_FLOW = 50;
my $FLOW_LEN = 20; ## in seconds
my $NUM_FLOW_PER_IP = 2;

my $DO_PKT_REORDERING = 1;
my $DO_PKT_UDP        = 1;
my $DO_FLOW_PKT_NUM   = 1;
my $DO_FLOW_LEN       = 1;
my $DO_FLOW_TTL_NUM   = 0;
my $DO_FLOW_TS_MONO   = 0;
my $DO_IP_FLOW_NUM    = 1;
my $DO_IP_USER_AGENT  = 0;
my $DO_IP_FREQ        = 0;
my $DO_IP_BOOT_TIME   = 0;

#############
# Constants
#############


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_parse_testbed/tshark";
my $output_dir = "../processed_data/subtask_parse_testbed/tshark";

my $exp;
my %filenames = ();
my $output_filename = "testbed";
my %ip_info = ();


#############
# check input
#############
if(@ARGV != 1) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$exp = $ARGV[0];
$output_filename = "testbed.$exp";

## EXP1
if($exp eq "exp1") {
    $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp2") {
    $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    # $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    # $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    # $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    # $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    # $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp3") {
    # $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    # $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    # $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    # $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    # $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    # $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    # $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    # $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    # $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    # $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp4") {
    # $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    # $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    # $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    # $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    # $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    # $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp5") {
    $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    # $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    # $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    # $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    # $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    # $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    # $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    # $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    # $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    # $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp6") {
    $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    # $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    # $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    # $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp7") {
    # $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    # $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    # $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    # $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    # $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    # $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    # $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    # $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    # $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    # $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    # $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    # $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp8") {
    $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    # $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    # $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    # $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    # $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp9") {
    # $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    # $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    # $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    # $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    # $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    # $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    # $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    # $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    # $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    # $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    # $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}
elsif($exp eq "exp10") {
    $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    # $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    # $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    # $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    # $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    # $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    # $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    # $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";
}
elsif($exp eq "exp11") {
    # $filenames{"2013.07.11.HTC.video.2min"}{OS} = "Android";
    # $filenames{"2013.07.11.HTC.video.2min"}{IP} = "9.9.1.1";
    $filenames{"2013.07.11.HTC.web.2min"}{OS} = "Android";
    $filenames{"2013.07.11.HTC.web.2min"}{IP} = "9.9.1.2";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_again"}{IP} = "9.9.1.6";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.iperf_dual"}{IP} = "9.9.1.8";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{OS} = "Android";
    # $filenames{"2013.07.12.Samsung.fc2video_iperf"}{IP} = "9.9.1.9";
    $filenames{"2013.07.15.Samsung.facebook"}{OS} = "Android";
    $filenames{"2013.07.15.Samsung.facebook"}{IP} = "9.9.1.11";

    $filenames{"2013.07.12.iPhone.facebook"}{OS} = "iPhone";
    $filenames{"2013.07.12.iPhone.facebook"}{IP} = "9.9.2.1";
    # $filenames{"2013.10.14.iphone.tr4.video"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr4.video"}{IP} = "9.9.2.4";
    # $filenames{"2013.10.14.iphone.tr5.web"}{OS} = "iPhone";
    # $filenames{"2013.10.14.iphone.tr5.web"}{IP} = "9.9.2.5";
    # $filenames{"2013.10.30.mac.chrome"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.chrome"}{IP} = "9.9.2.6";
    # $filenames{"2013.10.30.mac.youtube"}{OS} = "iPhone";
    # $filenames{"2013.10.30.mac.youtube"}{IP} = "9.9.2.7";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{OS} = "iPhone";
    $filenames{"2013.07.12.iphone.fc2video_iperf"}{IP} = "9.9.2.8";

    # $filenames{"2013.10.30.windows.ie"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.ie"}{IP} = "9.9.3.1";
    # $filenames{"2013.10.30.windows.youtube"}{OS} = "Windows";
    # $filenames{"2013.10.30.windows.youtube"}{IP} = "9.9.3.2";

    $filenames{"belch2umass-201201022-1.80"}{OS} = "Android";
    $filenames{"belch2umass-201201022-1.80"}{IP} = "9.9.4.80";
    # $filenames{"belch2umass-20121015-1.43"}{OS} = "Android";
    # $filenames{"belch2umass-20121015-1.43"}{IP} = "9.9.4.43";

    $filenames{"sjtu_wifi.Android.111.186.62.47"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.62.47"}{IP} = "9.9.5.1";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{OS} = "Android";
    $filenames{"sjtu_wifi.Android.111.186.63.92"}{IP} = "9.9.5.2";

    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{OS} = "Apple";
    $filenames{"sjtu_wifi.iPhone.111.186.61.28"}{IP} = "9.9.6.1";

    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.71"}{IP} = "9.9.7.1";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.10.7"}{IP} = "9.9.7.2";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.10"}{IP} = "9.9.7.3";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.118"}{IP} = "9.9.7.4";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.61"}{IP} = "9.9.7.5";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.61.64"}{IP} = "9.9.7.6";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.10"}{IP} = "9.9.7.7";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.14"}{IP} = "9.9.7.8";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{OS} = "Windows";
    $filenames{"sjtu_wifi.Windows.111.186.62.22"}{IP} = "9.9.7.9";
}


# $filenames{""}{OS} = "";
# $filenames{""}{IP} = "1.1.1.";


#############
# Main starts
#############

## read the filename
foreach my $filename (sort (keys %filenames)) {
    my $this_os = $filenames{$filename}{OS};
    my $new_ip  = $filenames{$filename}{IP};
    $ip_info{SRC}{$new_ip}{PREV_TS}{TIME} = -1;
    print "read the filename: $filename ($this_os, $new_ip)\n" if($DEBUG2);

    my $prev_rcv_time = 0;
    open FH, "bzcat $input_dir/$filename.txt.bz2 | " or die $!;
    while(<FH>) {
        chomp;
        print $_."\n" if($DEBUG0);

        my ($cnt, $rcv_time, $src_list, $dst_list, $sport_list, $dport_list, $id_list, $ttl_list, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $_);
        my @tmp = split(/,/, $src_list); my $src = $tmp[-1];
        @tmp = split(/,/, $dst_list); my $dst = $tmp[-1];
        @tmp = split(/,/, $sport_list); my $sport = $tmp[-1];
        @tmp = split(/,/, $dport_list); my $dport = $tmp[-1];
        @tmp = split(/,/, $id_list); my $id = $tmp[-1];
        @tmp = split(/,/, $ttl_list); my $ttl = $tmp[-1];
        $cnt += 0; $rcv_time += 0; $id = hex($id); $ttl += 0; $tsval += 0; $tsecr += 0; $wsscale += 0; $inflight += 0;
        print "  src=$src, dst=$dst, id=$id, ttl=$ttl, ts=$tsval, win scale=$wsscale, opt=$opt_kind, UA=$ua, flight bytes=$inflight\n" if($DEBUG0);

        my $new_ua = "$ua.$this_os";
        my $new_line = join("|", ($cnt, $rcv_time, $new_ip, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $new_ua, $inflight));


        ## filter out packets
        if($rcv_time < $prev_rcv_time) {
            print "  rcv time < prev rcv time\n";
            next;
        }
        $prev_rcv_time = $rcv_time;

        #############
        ## - pkt w/ reordering of Timestamp
        #############
        if($DO_PKT_REORDERING) {
            if($tsval > 0) {
                if($ip_info{SRC}{$new_ip}{PREV_TS}{TIME} > 0 and $tsval == $ip_info{SRC}{$new_ip}{PREV_TS}{TIME}) {
                    next;
                }
                elsif($ip_info{SRC}{$new_ip}{PREV_TS}{TIME} > 0 and $tsval <= $ip_info{SRC}{$new_ip}{PREV_TS}{TIME}) {
                    # print "prev: ".$ip_info{SRC}{$new_ip}{PREV_TS}{TIME}."\n"; 
                    # print "curr: $tsval\n";
                    print ".";
                    next;
                }
                $ip_info{SRC}{$new_ip}{PREV_TS}{TIME} = $tsval;
                # $ip_info{SRC}{$new_ip}{PREV_TS}{LINE} = $new_line;
            }
        }

        #############
        ## - pkt: UDP
        #############
        if($DO_PKT_UDP) {
            # print "o";
            next if($dport == 0);
        }


        ## packets we want
        $ip_info{SRC}{$new_ip}{RCV_TIME}{$rcv_time}{LINE}{$new_line} = 0;
        $ip_info{SRC}{$new_ip}{FLOW}{"$dst,$sport,$dport"}{RCV_TIME}{$rcv_time}{LINE} = $new_line;
        $ip_info{SRC}{$new_ip}{FLOW}{"$dst,$sport,$dport"}{TTL}{$ttl} = 1;
        $ip_info{SRC}{$new_ip}{FLOW}{"$dst,$sport,$dport"}{RCV_TIME2}{$rcv_time}{TX_TIME} = $tsval if($tsval > 0);
        $ip_info{SRC}{$new_ip}{UA}{$new_ua} = 0;
    }
    close FH;
}


##########################################################

my %ok_ip_info = ();
foreach my $this_ip (sort (keys %{ $ip_info{SRC} })) {
    print "$this_ip\n" if($DEBUG2);

    # my %ok_flow_info = ();
    foreach my $this_flow (keys %{ $ip_info{SRC}{$this_ip}{FLOW} }) {
        #############
        ## number of pkts per flow
        #############
        if($DO_FLOW_PKT_NUM) {
            # print "- flow: number of pkts per flow\n" if($DEBUG2);

            my $num_pkts = scalar(keys %{ $ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{RCV_TIME} });
            print "  flow: #pkt=$num_pkts\n";
            if($num_pkts > $NUM_PKT_PER_FLOW) {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 0;
                next;
            }
        }

        #############
        ## length of flow
        #############
        if($DO_FLOW_LEN) {
            # print "- flow: length of flow\n" if($DEBUG2);

            my @rx_times = (sort {$a <=> $b} (keys %{ $ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{RCV_TIME} }));
            my $flow_len = $rx_times[-1] - $rx_times[0];
            print "  flow: len=$flow_len\n";
            if($flow_len > $FLOW_LEN) {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 0;
                next;
            }
        }

        #############
        ## flow w/ multiple TTLs
        #############
        if($DO_FLOW_TTL_NUM) {
            # print "- flow: w/ multiple TTLs\n" if($DEBUG2);

            my $num_ttls = scalar(keys $ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{TTL});
            if($num_ttls == 1) {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 0;
                next;
            }
        }

        #############
        ## flow w/o monotonic TS
        #############
        if($DO_FLOW_TS_MONO) {
            # print "- flow: w/o monotonic TS\n" if($DEBUG2);

            my $is_mono = 1;
            my $prev_tx_time = -1;
            foreach my $rx_time (keys %{ $ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{RCV_TIME2} }) {
                my $tx_time = $ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{RCV_TIME2}{$rx_time}{TX_TIME};
                if($tx_time < $prev_tx_time) {
                    ## disorder
                    $is_mono = 0;
                    last;
                }
                $prev_tx_time = $tx_time;
            }

            if($is_mono == 1) {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 1;
            }
            else {
                $ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} = 0;
                next;
            }
        }


        #############
        ## Final step for this flow:
        ##   this flow is OK
        #############
        if($ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} == 1) {
            $ok_ip_info{SRC}{$this_ip}{OK_FLOWS}{$this_flow} = 1;
        }
        else {
            die "should not be here \n";
        }
    } ## end of flows


    #############
    ## - IPs: at least a flow has enough packet
    #############
    if($DO_IP_FLOW_NUM) {
        print "- IP: has enough flows\n" if($DEBUG2);
        
        my $num_flows = scalar(keys %{ $ok_ip_info{SRC}{$this_ip}{OK_FLOWS} });
        print "  # flows=$num_flows\n" if($DEBUG2);
        if($num_flows >= $NUM_FLOW_PER_IP) {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 1;
        }
        else {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 0;
            next;
        }
    }


    #############
    ## - IPs: has UA
    #############
    if($DO_IP_USER_AGENT) {
        print "- IP: has UA\n" if($DEBUG2);
        
        my @this_ua = keys %{ $ip_info{SRC}{$this_ip}{UA} };
        my @oss = Tethering::identify_os(\@this_ua);
        if(scalar(@oss) > 0) {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 1;
            print "  ".join(",". @oss)."\n";
        }
        else {
            $ok_ip_info{SRC}{$this_ip}{STATE} = 0;
            print "  no\n";
            next;
        }
    }


    #############
    ## Final step for this IP:
    ##   this IP is OK
    #############
    if($ok_ip_info{SRC}{$this_ip}{STATE} == 1) {
        $ok_ip_info{OK_SRC}{$this_ip} = 1;
    }
    else {
        die "should not be here (IP) \n";
    }
}

print "> # IPs: ".scalar(keys %{ $ok_ip_info{OK_SRC} })."\n";
print "    ".join("\n    ", (sort keys %{ $ok_ip_info{OK_SRC} }))."\n";


#############
## output the new file
#############
print "output the new file\n" if($DEBUG2);

if(-e "$output_dir/$output_filename.filter.txt.bz2") {
    my $cmd = "rm \"$output_dir/$output_filename.filter.txt.bz2\"";
    `$cmd`;
}

my %tmp = ();
foreach my $this_ip (sort (keys %{ $ip_info{SRC} })) {
    next if($ok_ip_info{SRC}{$this_ip}{STATE} != 1);

    foreach my $this_flow (keys %{ $ip_info{SRC}{$this_ip}{FLOW} }) { 
        next if($ok_ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{STATE} != 1);

        foreach my $rx_time (keys %{ $ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{RCV_TIME} }) { 
            my $line = $ip_info{SRC}{$this_ip}{FLOW}{$this_flow}{RCV_TIME}{$rx_time}{LINE};

            $tmp{RCV_TIME}{$rx_time}{LINE}{$line} = 1;
        }
    }
}

open FH_OUT, "> $output_dir/$output_filename.filter.txt" or die $!;
foreach my $rx_time (sort {$a <=> $b} (keys %{ $tmp{RCV_TIME} })) {
    foreach my $this_line (keys %{ $tmp{RCV_TIME}{$rx_time}{LINE} }) {
        print FH_OUT "$this_line\n";
    }
}
close FH_OUT;


#############
## compress the new output file
#############
print "compress the new output file\n" if($DEBUG2);

my $cmd = "bzip2 \"$output_dir/$output_filename.filter.txt\"";
`$cmd`;


