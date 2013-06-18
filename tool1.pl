#!/bin/perl 

use strict;


## output
##  format:
##  ./output/detect.TTL.summary
##  <1. # tethered clients>, <2. # clients>, 
##  <3. # tethered pkts>, <4. # pkts>, 
##  <5. tethered traffic (bytes)>, <6. traffic (bytes)>, 
##  <7. intra-flow tput ratio>, <8. intra-flow #pkt ratio>, <9. intra-flow pkt len entropy ratio>
##  <10. inter-flow tput ratio>, <11. inter-flow #pkt ratio>, <12. inter-flow pkt len entropy ratio>
##  <13. inter-flow inter arrival time mean ratio>, <14. inter-flow inter arrival time stdev ratio>
##  
open FH_SUMMARY, "> ./output/detect.TTL.summary";

my $done = 0;

foreach my $file_id (49 .. 199, 0 .. 48) {
    my $file = "./output/detect.TTL.$file_id.log";
    if (!(-e $file)) {
        print "no such file: $file\n";
        next;
    }
    print `date`;
    print "  $file\n";

    open FH, $file or die $!;
    while(<FH>) {
        if($_ =~ /TTL:/) {
            next;
        }
        elsif($_ =~ /number of tethering flows: (\d+) \/ (\d+)/) {
            ## unique source IPs
            print FH_SUMMARY "$1, $2, ";
        }
        elsif($_ =~ /number of tethering pkts: (\d+) \/ (\d+)/) {
            ## pkts
            print FH_SUMMARY "$1, $2, ";
        }
        elsif($_ =~ /number of tethering traffic: (\d+) \/ (\d+)/) {
            ## tput
            print FH_SUMMARY "$1, $2, ";
        }
        elsif($_ =~ /intra flow, the ratio of tethered to non-tethered period:/) {
            my $line = <FH>;
            if($line =~ /tput: (\d+\.\d+)/) {
                ## intra flow: tput ratio of tethered period to non-tethered period in a flow
                print FH_SUMMARY "$1, ";
            }
            else {
                die "wrong format in intra flow tput analysis\n\t$line\n";
            }

            
            $line = <FH>;
            if($line =~ /pkt: (\d+\.\d+)/) {
                ## intra flow: pkt ratio of tethered period to non-tethered period in a flow
                print FH_SUMMARY "$1, ";
            }
            else {
                die "wrong format in intra flow pkt analysis\n\t$line\n";
            }


            $line = <FH>;
            if($line =~ /entrooy: (\d+\.\d+)/) {
                ## intra flow: entropy ratio of tethered period to non-tethered period in a flow
                print FH_SUMMARY "$1, ";
            }
            else {
                die "wrong format in intra flow entropy analysis\n\t$line\n";
            }
        }
        elsif($_ =~ /inter flow, the ratio of tethered to non-tethered flow:/) {
            my $line = <FH>;
            if($line =~ /tput: (\d+\.\d+)/) {
                ## inter flow: tput ratio of tethered flwo to non-tethered flow
                print FH_SUMMARY "$1, ";
            }
            else {
                die "wrong format in inter flow tput analysis\n\t$line\n";
            }

            
            $line = <FH>;
            if($line =~ /pkt: (\d+\.\d+)/) {
                ## inter flow: pkt ratio of tethered flow to non-tethered flow
                print FH_SUMMARY "$1, ";
            }
            else {
                die "wrong format in inter flow pkt analysis:\n\t$line\n";
            }


            $line = <FH>;
            if($line =~ /entrooy: (\d+\.\d+)/) {
                ## inter flow: entropy ratio of tethered flow to non-tethered flow
                print FH_SUMMARY "$1, ";
            }
            else {
                die "wrong format in inter flow entropy analysis\n\t$line\n";
            }

            $line = <FH>;
            if($line =~ /inter-arrival time mean: (\d+\.\d+)/) {
                ## inter flow: inter-arrival time mean ratio of tethered flow to non-tethered flow
                print FH_SUMMARY "$1, ";
            }
            else {
                die "wrong format in inter flow inter-arrival time mean analysis\n\t$line\n";
            }

            $line = <FH>;
            if($line =~ /inter-arrival time stdev: (\d+\.\d+)/) {
                ## inter flow: inter-arrival time stdev ratio of tethered flow to non-tethered flow
                print FH_SUMMARY "$1, ";

                $done = 1;
            }
            else {
                die "wrong format in inter flow inter-arrival time stdev analysis\n\t$line\n";
            }
            
        }
        else {
            if($done == 1) {
                $done = 0;
                next;
            }
            die "wrong format: $_\n";
        }
    }
    close FH;
}

close FH_SUMMARY;


