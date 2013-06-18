#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/14 @ Narus 
##
## Read IPs of tethered clients detected by different methods, and validate the overlapping
##
## - input: 
##     IP of tethered clients.
##      a) TTL (whole trace): ./tethered_clients/TTL_whole_trace.<file id>.txt
##      b) TTL (one second) : ./tethered_clients/TTL_one_second.<file id>.txt
##
## - output:
##      a) How many clients are detected by 1/2/3/4/5... methods
##          ./tethered_clients/summary.<file id>.number_methods.txt
##          format:
##          <number of methods> <number of tethered clients>
##      b) overlapping between methods
##          ./tethered_clients/summary.<file id>.cross_validation.txt
##          format:
##          <method1> <method2> <overlap> <only by former> <only by latter> <# total detected clients> <overlap ratio> <only by former ratio> <only by latter ratio>
##
##  e.g.
##      perl cross_validate_detected_ip.pl 49
##
##################################################


use strict;

use List::Util qw(max min);


#####
## constant
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug



#####
## variables
my $input_dir = "./tethered_clients";
my $input_all_client_dir = "./output";
my $output_dir = "./tethered_clients";
my @methods = ("TTL_one_second",
               "TTL_whole_trace");

my $file_id;

my %tether_info;        ## to store the information of tethered IP
                        ## @{ip}{ip}{detected_methods} - which methods detect this IP as a tethered client
                        ## %{detected_method_number}{detected_method_number} - how many clients are detected by 1/2/3/4/5... methods


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

my $number_clients = `cat $input_all_client_dir/file.$file_id.ttl.txt | wc -l` + 0;
print "there are $number_clients clients in file $file_id\n" if($DEBUG1);


foreach my $this_method (@methods) {
    my $this_method_file = "$this_method.$file_id.txt";
    print `date` if($DEBUG2);
    print "  $this_method_file\n" if($DEBUG2);


    open FH, "$input_dir/$this_method_file" or die $!;
    while(my $this_ip = <FH>) {
        chomp $this_ip;
        print $this_ip."\n" if($DEBUG1);


        push(@{$tether_info{ip}{$this_ip}{detected_methods}}, $this_method);


        #####
        ## DEBUG
        #####
        if($DEBUG0) {
            foreach my $m1 (0 .. scalar(@{$tether_info{ip}{$this_ip}{detected_methods}})-1) {
                foreach my $m2 ($m1+1 .. scalar(@{$tether_info{ip}{$this_ip}{detected_methods}})-1) {
                    if($tether_info{ip}{$this_ip}{detected_methods}[$m1] eq $tether_info{ip}{$this_ip}{detected_methods}[$m2]) {
                        print "$this_ip\n";
                        print "the detected method shouldn't duplicate\n";
                        print "$m1:".$tether_info{ip}{$this_ip}{detected_methods}[$m1]."\n";
                        print "$m2:".$tether_info{ip}{$this_ip}{detected_methods}[$m2]."\n";
                        die "\n";
                    }
                }
            }
        }
    }
    close FH;
}


#####
## Process 
print "\nStart to Process:\n" if($DEBUG2);


#####
## Number of detected methods
foreach my $this_ip (keys %{$tether_info{ip}}) {
    my $num_methods = scalar(@{$tether_info{ip}{$this_ip}{detected_methods}});
    die "# methods shouldn't be 0\n" if($num_methods == 0);

    $tether_info{detected_method_number}{$num_methods} ++;
}

open FH, "> $output_dir/summary.$file_id.number_methods.txt" or die $!;
foreach my $this_num (1 .. scalar(@methods)) {
    if(exists $tether_info{detected_method_number}{$this_num}) {
        print FH "$this_num, ".$tether_info{detected_method_number}{$this_num}.", ".($tether_info{detected_method_number}{$this_num} / $number_clients)."\n";
    }
    else {
        print FH "$this_num, 0, 0\n";
    }
    
}
close FH;



#####
## overlapping with each other
## format:
##   <method1> <method2> <overlap> <only by former> <only by latter> <# total detected clients> <overlap ratio> <only by former ratio> <only by latter ratio>
open FH, "> $output_dir/summary.$file_id.cross_validation.txt" or die $!;
foreach my $ind1 (0 .. scalar(@methods)-1) {
    foreach my $ind2 ($ind1+1 .. scalar(@methods)-1) {
        my $method1 = $methods[$ind1];
        my $method2 = $methods[$ind2];
        print "$method1, $method2\n" if($DEBUG2);
        

        my $cnt_both = 0;       ## number of IPs detected by both methods
        my $cnt_former = 0;     ## number of IPs detected by method1
        my $cnt_latter = 0;     ## number of IPs detected by method2


        foreach my $this_ip (keys %{$tether_info{ip}}) {

            my $detected_methods_str = join(",", (@{$tether_info{ip}{$this_ip}{detected_methods}}));


            if($detected_methods_str =~ /$method1/ and $detected_methods_str =~ /$method2/) {
                ## detected by both methods
                $cnt_both ++;
            }
            elsif($detected_methods_str =~ /$method1/) {
                ## detected by the former method
                $cnt_former ++;
            }
            elsif($detected_methods_str =~ /$method2/) {
                ## detected by the latter method
                $cnt_latter ++;
            }
        }


        print FH "$method1, $method2, $cnt_both, $cnt_former, $cnt_latter, $number_clients, ".($cnt_both / $number_clients).", ".($cnt_former / $number_clients).", ".($cnt_latter / $number_clients)."\n";

    }
}
close FH;