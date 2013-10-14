#!/bin/perl 

########################################
## Author: Yi-Chao Chen 
## 2013/06/14 @ Narus 
##
## Some time ago, the initial TTL of Windows is 64.
## Check if there are any clients whose initial TTL is 64.
##
## - input: ../output/file.$file_id.ttl.txt
##
## - output:
##      ./output
##      <# client> <# normal client w/ TTL_X> <...> <# tethered client w/ TTL_X> <...>
##
##  e.g.
##      perl check_windows_ttl.pl
##
########################################

use strict;


#####
## variables
my $input_dir = "../output";
my $output_dir = "./output";
my $output_file = "ttl64.summary";

my @ttl_to_cnt = (62 .. 65);

#####
## main starts here
open FH_SUMMARY, "> $output_dir/$output_file" or die $!;

# foreach my $file_id (49 .. 199, 0 .. 48) {
foreach my $file_id (49) {
    my $cnt_clients = 0;
    my %cnt_ttls;           ## cnt_ttls{tether_client}{ttl value}
                            ## cnt_ttls{normal_client}{ttl value}


    #####
    ## get file name
    my $file = "$input_dir/file.$file_id.ttl.txt";
    if (!(-e $file)) {
        print "no such file: $file\n";
        next;
    }
    print `date`;
    print "  $file\n";


    #####
    ## open file 
    ##   format: <IP> <# TTL> <TTL1> <TTL2> <TTL3> ...
    open FH, $file or die $!;
    while(<FH>) {
        my ($ip_pair, $ttl_cnt, @ttls) = split(/, /, $_);
        $ttl_cnt += 0;
        die "wrong format\n" if($ttl_cnt != scalar(@ttls));
        
        ## a new client
        $cnt_clients ++;


        ## normal client
        if($ttl_cnt == 1) {
            my $this_ttl = (shift @ttls) + 0;

            foreach my $target_ttl (@ttl_to_cnt) {
                if($this_ttl == $target_ttl) {
                    $cnt_ttls{normal_client}{$this_ttl} ++;
                }
            }
        }
        ## tethered client
        elsif($ttl_cnt > 1) {
            foreach my $this_ttl (@ttls) {
                $this_ttl += 0;
                foreach my $target_ttl (@ttl_to_cnt) {
                    if($this_ttl == $target_ttl) {
                        $cnt_ttls{tether_client}{$this_ttl} ++;
                    }
                }
            }
        }

        else {
            die "weird TTL count\n";
        }
        
    }
    close FH;


    #####
    ## output
    print FH_SUMMARY "# client_cnt, ";
    foreach my $target_ttl (@ttl_to_cnt) {
        print FH_SUMMARY "normal_client_TTL_$target_ttl, ";
    }
    foreach my $target_ttl (@ttl_to_cnt) {
        print FH_SUMMARY "tether_client_TTL_$target_ttl, ";
    }
    print FH_SUMMARY "\n";

    print FH_SUMMARY "$cnt_clients, ";
    foreach my $target_ttl (@ttl_to_cnt) {
        if (exists($cnt_ttls{normal_client}{$target_ttl})) {
            print FH_SUMMARY "".$cnt_ttls{normal_client}{$target_ttl}.", ";
        }
        else {
            print FH_SUMMARY "0, ";
        }
        
    }
    foreach my $target_ttl (@ttl_to_cnt) {
        if (exists($cnt_ttls{tether_client}{$target_ttl})) {
            print FH_SUMMARY "".$cnt_ttls{tether_client}{$target_ttl}.", ";
        }
        else {
            print FH_SUMMARY "0, ";
        }
    }
    print FH_SUMMARY "\n";

}

close FH_SUMMARY;


