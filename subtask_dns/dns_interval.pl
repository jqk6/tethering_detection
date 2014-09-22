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
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
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
my $input_dir  = "../processed_data/subtask_dns/dns_trace";
my $output_dir = "../processed_data/subtask_dns/interval";

my @files = ("dns.youtube.pcap.txt");

my %dns_info;

# my @black_list = ("fbcdn", "facebook", "fbexternal")


#############
# check input
#############
# if(@ARGV != 1) {
#     print "wrong number of input: ".@ARGV."\n";
#     exit;
# }
# $ARGV[0];


#############
# Main starts
#############


#############
## read files
#############
foreach my $file (@files) {
    print "READ file: $file\n" if($DEBUG2);

    my %dns_server_map;

    open FH, "$input_dir/$file" or die "$input_dir/$file\n".$!;
    while(<FH>) {
        chomp;

        my ($time, $src, $dst, $id, $resp, $type, $name, $ttls) = split(/\|/, $_);
        $type = hex($type);

        print $_."\n" if($DEBUG0);
        print join(", ", ($time, $src, $dst, $id, $resp, $type, $name, $ttls))."\n" if($DEBUG0);

        if($resp == 1) {
            print "  response\n" if($DEBUG0);
        }
        else {
            if(exists $dns_server_map{$dst}) {
                $dst = $dns_server_map{$dst};
            }
            else {
                my $map_index = scalar(keys %dns_server_map);
                $dst = $map_index;
            }

            $dns_info{FILE}{$file}{REQ}{DNS}{$dst}{TYPE}{$type}{NAME}{$name}{TIME}{$time} = 1;
            if(scalar(@files) > 1) {
                $dns_info{FILE}{COMB}{REQ}{DNS}{$dst}{TYPE}{$type}{NAME}{$name}{TIME}{$time} = 1;
            }
        }

    }
    close FH;
}


#############
## check repeat requests
#############
foreach my $file (keys %{ $dns_info{FILE} }) {
    print "Check interval of repeat requests: $file\n" if($DEBUG2);

    my @itvls = ();
    my $num_uniq_dns = 0;    ## number of unique dns
    my $num_repeat_dns = 0;  ## number of dns which appear more than once
    my $num_dns = 0;  ## total number of dns requests
    foreach my $dns (keys %{ $dns_info{FILE}{$file}{REQ}{DNS} }) {
        foreach my $type (keys %{ $dns_info{FILE}{$file}{REQ}{DNS}{$dns}{TYPE} }) {
            ## XXX: only consider A and AAAA request for now
            next if($type != 1 and $type != 28);  
            
            foreach my $name (keys %{ $dns_info{FILE}{$file}{REQ}{DNS}{$dns}{TYPE}{$type}{NAME} }) {
                $num_uniq_dns ++;

                my @times = (keys %{ $dns_info{FILE}{$file}{REQ}{DNS}{$dns}{TYPE}{$type}{NAME}{$name}{TIME} });
                $num_dns += scalar(@times);

                if(scalar(@times) > 1) {
                    # print "    $name: ".scalar(@times)."\n" if($DEBUG3);
                    $num_repeat_dns ++;

                    my $prev = -1;
                    foreach my $time (sort {$a <=> $b} (@times)) {
                        if($prev == -1) {
                            $prev = $time;
                            next;
                        }
                        my $itvl = $time - $prev;
                        die "interval $itvl < 0\n" if($itvl < 0);

                        push(@itvls, $itvl) if($itvl > 3);


                        if($itvl < 60) {
                            print "    $name (".scalar(@times)."): $itvl\n" if($DEBUG3);
                        }


                        print "    $name (".scalar(@times)."): $itvl\n" if($DEBUG3);
                    }
                }
            }
        }
    }

    print "  # uniq dns = $num_uniq_dns\n";
    print "  # repeat dns = $num_repeat_dns\n";
    print "  # total dns = $num_dns\n";
    print "  avg interval = ".MyUtil::average(\@itvls)."\n";
    print "  itvls = ".join(", ", @itvls)."\n";

    open FH, "> $output_dir/$file" or die $!;
    print FH join("\n", sort @itvls)."\n";
    close FH;
}
