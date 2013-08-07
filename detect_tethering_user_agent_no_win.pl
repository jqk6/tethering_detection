#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/07/24 @ Narus 
##
## Read in results from "analyze_sprint_http_user_agents.pl" and detect tethering using the number of OSs and devices.
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_http_user_agents.pl", i.e.
##     ./output/
##      file.<file id>.user_agent.txt
##      <ip> <# OSs> <# devices> <OS1> <OS2> ... <device1> <device2> ...
##
## - output:
##      IP of tethered clients.
##          ./tethered_clients/User_agent.no_windows.<file id>.txt
##
##  e.g.
##      perl detect_tethering_user_agent_no_win.pl 49
##
##################################################


use strict;

use MyUtil;


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
                    ## {IP}{ip}{OSS}{os}
                    ## {IP}{ip}{DEVICES}{devices}
                    ## {TETHERED_IP}{tethered ip}


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
##  OS and device
my $file_name = "file.$file_id.user_agent.txt";
open FH, "$input_dir/$file_name" or die $!."\n$file_name\n";
while(<FH>) {
    my ($ip, $os_cnt, $device_cnt, @oss_devices) = split(/, /, $_);
    my (@oss, @devices);
    ## convert to numbers
    $os_cnt += 0;
    $device_cnt += 0;

    foreach my $ind (0 .. ($os_cnt+$device_cnt-1)) {
        if($ind < $os_cnt) {
            push(@oss, $oss_devices[$ind]);
        }
        else {
            push(@devices, $oss_devices[$ind]);
        }
    }

    print "$ip: os ($os_cnt) = [".join(",", @oss)."], devices ($device_cnt) = [".join(",", @devices)."]\n" if($DEBUG2); 

    @{ $ip_info{IP}{$ip}{OSS} } = @oss;
    @{ $ip_info{IP}{$ip}{DEVICES} } = @devices;
}
close FH;    
## end readin IP info
#######################################


#####
## find tethering using # of OSs and devices
my $cnt_total = 0;
my $cnt_tether = 0;
my $cnt_tether_no_windows = 0;
foreach my $this_ip (keys %{ $ip_info{IP} }) {
    $cnt_total ++;
    if(scalar(@{ $ip_info{IP}{$this_ip}{OSS} }) > 1) { 
        $cnt_tether ++;

        my $has_windows = 0;
        foreach my $this_os (@{ $ip_info{IP}{$this_ip}{OSS} }) {
            if($this_os =~ /Windows/) {
                $has_windows = 1;
                last;
            }
        }


        if(scalar(@{ $ip_info{IP}{$this_ip}{OSS} }) - $has_windows > 1) { 
            $cnt_tether_no_windows ++;
            $ip_info{TETHERED_IP}{$this_ip} = 1;
        }
    }
    elsif(scalar(@{ $ip_info{IP}{$this_ip}{DEVICES} }) > 1) {
        $cnt_tether ++;

        my $has_windows = 0;
        foreach my $this_os (@{ $ip_info{IP}{$this_ip}{DEVICES} }) {
            if($this_os =~ /Windows/) {
                $has_windows = 1;
                last;
            }
        }


        if(scalar(@{ $ip_info{IP}{$this_ip}{DEVICES} }) - $has_windows > 1) { 
            $cnt_tether_no_windows ++;
            $ip_info{TETHERED_IP}{$this_ip} = 1;
        }
    }

}


#####
## output
my $file_output = "User_agent.no_windows.$file_id.txt";
open FH, "> $output_dir/$file_output" or die $!;
foreach my $this_ip (keys %{ $ip_info{TETHERED_IP} }) {
    print FH $this_ip."\n";
}
close FH;

if($DEBUG2) {
    print "total IPs: $cnt_total\n";
    print "total tethered IPs: $cnt_tether\n";
    print "tethered IPs without using Windows: $cnt_tether_no_windows\n"
}


1;



#####
## functions
