#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/14 @ Narus 
##
## Generate IP's ID field timeseries of non-tethered users. 
## We want to see if there is difference between ID from tehtered users and non-tethered users.
##
## - input: file_id
##     The file ID of 3-hr Sprint Mobile Dataset.
##     This program uses this ID to look up the output files from "analyze_sprint_text.pl", i.e.
##     ./output/
##     a) file.<id>.tput.ts.txt: 
##         total throughput timeseries
##     b) file.<id>.pkt.ts.txt
##         total packet number timeseries
##     c) file.<id>.ids.ts.txt
##         IP ID of each packet of each flow
##     d) file.<id>.ttl.txt
##         TTL of each flow
##     e) file.<id>.ttl.ts.txt
##         timeseries of # of unique TTLs of each flow
##     f) file.<id>.tput.ts.txt
##         timeseries of tput of each flow
##     g) file.<id>.pkt.ts.txt
##         timeseries of # of packets of each flow
##     i) file.$file_id.len_entropy.ts.txt
##         timeseries of packet len entropy of each flow
##
## - output:
##      a) fig: generate IDs timeseries of non-tethered clients detected by TTL
##          ./figures_ttl/tehtered.<file_id>.<IP>.ids.txt.eps
##
##  e.g.
##      perl detect_tethering.pl 49
##
##################################################


use strict;

use List::Util qw(max min);


#####
## constant
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug

my $PLOT_THRESHOLD = 1000;


#####
## variables
my $input_dir = "../output";
my $figure_dir = "./figures_ttl";
my $figure_data_dir = "$figure_dir/data";

my $file_id;

my $total_pkt_byte = 0;
my $total_pkt_cnt = 0;
my $total_flow_cnt = 0;

my %tether_info;    ## statistic of all tethering detection
                    ## %{ttl}{ip_pair}
                    ## ${ttl}{pkt_byte}
                    ## ${ttl}{pkt_cnt}

                    ## @{ttl}{intra_ratio_tput}
                    ## @{ttl}{intra_ratio_pkt}
                    ## @{ttl}{intra_ratio_entropy}

                    ## @{ttl}{tether_tput}
                    ## @{ttl}{tether_pkt}
                    ## @{ttl}{tether_entropy}

                    ## @{ttl}{normal_tput}
                    ## @{ttl}{normal_pkt}
                    ## @{ttl}{normal_entropy}

                    ## ${ttl}{inter_ratio_tput}
                    ## ${ttl}{inter_ratio_pkt}
                    ## ${ttl}{inter_ratio_entropy}

my %ip_info;        ## to store the information of each IP
                    ## @{ip}{id_ts} - in pkt order, not in second
                    ## @{ip}{ttl_ts}
                    ## @{ip}{tput_ts}
                    ## @{ip}{pkt_ts}
                    ## @{ip}{entropy_ts}



#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_id = $ARGV[0];
print "file ID = $file_id\n" if($DEBUG1);
my $file_tput_ts = "file.$file_id.tput.ts.txt";
my $file_pkt_ts = "file.$file_id.pkt.ts.txt";
my $file_len_entropy_ts = "file.$file_id.len_entropy.ts.txt";
my $file_ttl_ts = "file.$file_id.ttl.ts.txt";
my $file_ids_ts = "file.$file_id.ids.ts.txt";


#####
## main starts here


#######################################
## read in ip info:
##
##  tput
open FH_TPUT, "$input_dir/$file_tput_ts" or die $!;
while(<FH_TPUT>) {
    ## collect total info
    $total_flow_cnt ++;

    my ($ip_pair, @tput_ts) = split(/, /, $_);
    foreach (0 .. @tput_ts-1) {
        ## convert to numbers
        $tput_ts[$_] += 0;

        ## collect total info
        $total_pkt_byte += $tput_ts[$_];
    }
    @{$ip_info{$ip_pair}{tput_ts}} = @tput_ts;
    print $ip_pair.": ".join(",", @{$ip_info{$ip_pair}{tput_ts}})."\n" if($DEBUG1);
}
close FH_TPUT;

##  pkt
open FH_PKT, "$input_dir/$file_pkt_ts" or die $!."\n$input_dir/$file_pkt_ts\n";
while(<FH_PKT>) {
    my ($ip_pair, @pkt_ts) = split(/, /, $_);
    foreach (0 .. @pkt_ts-1) {
        ## convert to numbers
        $pkt_ts[$_] += 0;

        ## collect total info
        $total_pkt_cnt += $pkt_ts[$_];
    }
    @{$ip_info{$ip_pair}{pkt_ts}} = @pkt_ts;
    print $ip_pair.": ".join(",", @{$ip_info{$ip_pair}{pkt_ts}})."\n" if($DEBUG1);
}
close FH_PKT;

##  ttl
open FH_TTL, "$input_dir/$file_ttl_ts" or die $!;
while(<FH_TTL>) {
    my ($ip_pair, @ttl_ts) = split(/, /, $_);
    foreach (0 .. @ttl_ts-1) {
        ## convert to numbers
        $ttl_ts[$_] += 0;
    }
    @{$ip_info{$ip_pair}{ttl_ts}} = @ttl_ts;
    print $ip_pair.": ".join(",", @{$ip_info{$ip_pair}{ttl_ts}})."\n" if($DEBUG1);
}
close FH_TTL;

##  entropy
open FH_ENT, "$input_dir/$file_len_entropy_ts" or die $!;
while(<FH_ENT>) {
    my ($ip_pair, @entropy_ts) = split(/, /, $_);
    foreach (0 .. @entropy_ts-1) {
        ## convert to numbers
        $entropy_ts[$_] += 0;
    }
    @{$ip_info{$ip_pair}{entropy_ts}} = @entropy_ts;
    print $ip_pair.": ".join(",", @{$ip_info{$ip_pair}{entropy_ts}})."\n" if($DEBUG1);
}
close FH_ENT;

##  IP ID
open FH_ID, "$input_dir/$file_ids_ts" or die $!;
while(<FH_ID>) {
    my ($ip_pair, $num_of_pkt, @id_ts) = split(/, /, $_);
    ## convert to numbers
    $num_of_pkt += 0;
    foreach (0 .. @id_ts-1) {
        $id_ts[$_] += 0;
    }
    @{$ip_info{$ip_pair}{id_ts}} = @id_ts;
    print $ip_pair." ($num_of_pkt): ".join(",", @{$ip_info{$ip_pair}{id_ts}})."\n" if($DEBUG1);
}
close FH_ID;

##
#######################################



#####
## find tethering using TTL
foreach my $this_ip_pair (keys %ip_info) {
    my $tether_detected_ttl = 0;

    ## for this flow, if this second is tethered, what are the tput, pkt cnt, entropy
    my $this_flow_tether_sec = 0;
    my $this_flow_tether_tput = 0;
    my $this_flow_tether_pkt = 0;
    my $this_flow_tether_entropy = 0;

    ## for this flow, if this second is not tethered, what are the tput, pkt cnt, entropy
    my $this_flow_normal_sec = 0;
    my $this_flow_normal_tput = 0;
    my $this_flow_normal_pkt = 0;
    my $this_flow_normal_entropy = 0;
    

    #####
    ## check each second, if the TTL > 1
    foreach my $ind (0 ... scalar(@{$ip_info{$this_ip_pair}{ttl_ts}})-1) {
        my $this_ttl = $ip_info{$this_ip_pair}{ttl_ts}[$ind];
        my $this_tput = $ip_info{$this_ip_pair}{tput_ts}[$ind];
        my $this_pkt = $ip_info{$this_ip_pair}{pkt_ts}[$ind];
        my $this_entropy = $ip_info{$this_ip_pair}{entropy_ts}[$ind];

        if($this_ttl > 1) {
            ## tethered
            $tether_detected_ttl = 1;

            $this_flow_tether_sec ++;
            $this_flow_tether_tput += $this_tput;
            $this_flow_tether_pkt += $this_pkt;
            $this_flow_tether_entropy += $this_entropy;
            
        }
        elsif($this_ttl == 1) {
            ## no tethering according to TTL

            $this_flow_normal_sec ++;
            $this_flow_normal_tput += $this_tput;
            $this_flow_normal_pkt += $this_pkt;
            $this_flow_normal_entropy += $this_entropy;
        }
        elsif($this_ttl == 0) {
            ## no traffic at this second
        }
        else {
            die "should not be here\n";
        }
    }

    if(($this_flow_tether_sec + $this_flow_normal_sec) == 0) {
        next;
    }


    #####
    ## avg statistics
    if($this_flow_tether_sec != 0 && $this_flow_normal_sec != 0) {
        my $this_flow_tether_avg_tput = $this_flow_tether_tput / $this_flow_tether_sec;
        my $this_flow_tether_avg_pkt = $this_flow_tether_pkt / $this_flow_tether_sec;
        my $this_flow_tether_avg_entropy = $this_flow_tether_entropy / $this_flow_tether_sec;
    
        my $this_flow_normal_avg_tput = $this_flow_normal_tput / $this_flow_normal_sec;
        my $this_flow_normal_avg_pkt = $this_flow_normal_pkt / $this_flow_normal_sec;
        my $this_flow_normal_avg_entropy = $this_flow_normal_entropy / $this_flow_normal_sec;

        push(@{$tether_info{ttl}{intra_ratio_tput}}, $this_flow_tether_avg_tput / $this_flow_normal_avg_tput);
        push(@{$tether_info{ttl}{intra_ratio_pkt}}, $this_flow_tether_avg_pkt / $this_flow_normal_avg_pkt);
        push(@{$tether_info{ttl}{intra_ratio_entropy}}, $this_flow_tether_avg_entropy / $this_flow_normal_avg_entropy) if($this_flow_normal_avg_entropy != 0);
    }
    

    #####
    ## tethering detected!!!
    if($tether_detected_ttl == 1) {
        
        ## XXX: all traffic belongs to this IP pair are considered tethered, not necessary to be true...
        my $flow_pkt_cnt = 0;   ## used to determine if to plot the flow
        foreach my $this_pkt_cnt (@{$ip_info{$this_ip_pair}{pkt_ts}}) {
            $tether_info{ttl}{pkt_cnt} += $this_pkt_cnt;
            $flow_pkt_cnt += $this_pkt_cnt; 
        }

        foreach my $this_pkt_byte (@{$ip_info{$this_ip_pair}{tput_ts}}) {
            $tether_info{ttl}{pkt_byte} += $this_pkt_byte;
        }


        ## update tether info
        $tether_info{ttl}{ip_pair}{$this_ip_pair} = 1;
        push(@{$tether_info{ttl}{tether_tput}}, ($this_flow_tether_tput + $this_flow_normal_tput) / ($this_flow_tether_sec + $this_flow_normal_sec));
        push(@{$tether_info{ttl}{tether_pkt}}, ($this_flow_tether_pkt + $this_flow_normal_pkt) / ($this_flow_tether_sec + $this_flow_normal_sec));
        push(@{$tether_info{ttl}{tether_entropy}}, ($this_flow_tether_entropy + $this_flow_normal_entropy) / ($this_flow_tether_sec + $this_flow_normal_sec));


        # #####
        # ## plot some figures for tethered clients
        # if($flow_pkt_cnt > $PLOT_THRESHOLD) {
    
        #     ##  a) IP ID
        #     open FH, "> $figure_data_dir/tehtered.$file_id.$this_ip_pair.ids.txt" or die $!;
        #     my @sorted_ids = sort {$a <=> $b} (@{$ip_info{$this_ip_pair}{id_ts}});
        #     foreach my $i (0 .. scalar(@sorted_ids)-1) {
        #         print FH "".$ip_info{$this_ip_pair}{id_ts}[$i].", ".$sorted_ids[$i]."\n";
        #     }
        #     # print FH join("\n", @{$ip_info{$this_ip_pair}{id_ts}})."\n";
        #     close FH;
        #     my $escape_figure_dir = $figure_dir;
        #     $escape_figure_dir =~ s/\//\\\//g;
        #     my $escape_figure_data_dir = $figure_data_dir;
        #     $escape_figure_data_dir =~ s/\//\\\//g;
        #     system("sed 's/FILENAME/tehtered.$file_id.$this_ip_pair.ids.txt/;s/FIGDIR/$escape_figure_dir/;s/DATADIR/$escape_figure_data_dir/' plot_id.plot.mother > plot_id.plot");
        #     system("gnuplot plot_id.plot");
        #     system("rm plot_id.plot");


        #     ##  b) entropy, throughput, pkt, ttl
        #     open FH, "> $figure_data_dir/tehtered.$file_id.$this_ip_pair.ts.txt" or die $!;
        #     my $max_tput = max(@{$ip_info{$this_ip_pair}{tput_ts}});
        #     my $max_pkt = max(@{$ip_info{$this_ip_pair}{pkt_ts}});
        #     my $max_entropy = max(@{$ip_info{$this_ip_pair}{entropy_ts}});
        #     foreach my $i (0 .. scalar(@{$ip_info{$this_ip_pair}{ttl_ts}})-1) {
        #         print FH "".$ip_info{$this_ip_pair}{ttl_ts}[$i].", ".($ip_info{$this_ip_pair}{tput_ts}[$i] / $max_tput).", ".($ip_info{$this_ip_pair}{pkt_ts}[$i] / $max_pkt).", ";
                
        #         if($max_entropy != 0) {
        #             print FH "".($ip_info{$this_ip_pair}{entropy_ts}[$i] / $max_entropy)."\n";
        #         }
        #         else {
        #             print FH "0\n";
        #         }
                
        #     }
        #     close FH;
        #     system("sed 's/FILENAME/tehtered.$file_id.$this_ip_pair.ts.txt/;s/FIGDIR/$escape_figure_dir/;s/DATADIR/$escape_figure_data_dir/' plot_ts.plot.mother > plot_ts.plot");
        #     system("gnuplot plot_ts.plot");
        #     system("rm plot_ts.plot");
        # }
    }

    else {
        ## do not detect tethering for this flow

        ## update tether info
        push(@{$tether_info{ttl}{normal_tput}}, ($this_flow_tether_tput + $this_flow_normal_tput) / ($this_flow_tether_sec + $this_flow_normal_sec));
        push(@{$tether_info{ttl}{normal_pkt}}, ($this_flow_tether_pkt + $this_flow_normal_pkt) / ($this_flow_tether_sec + $this_flow_normal_sec));
        push(@{$tether_info{ttl}{normal_entropy}}, ($this_flow_tether_entropy + $this_flow_normal_entropy) / ($this_flow_tether_sec + $this_flow_normal_sec));


        #####
        ## plot some figures for tethered clients
        my $flow_pkt_cnt = 0;   ## used to determine if to plot the flow
        foreach my $this_pkt_cnt (@{$ip_info{$this_ip_pair}{pkt_ts}}) {
            $flow_pkt_cnt += $this_pkt_cnt; 
        }
        if($flow_pkt_cnt > $PLOT_THRESHOLD) {
    
            ##  a) IP ID
            open FH, "> $figure_data_dir/normal.$file_id.$this_ip_pair.ids.txt" or die $!;
            my @sorted_ids = sort {$a <=> $b} (@{$ip_info{$this_ip_pair}{id_ts}});
            foreach my $i (0 .. scalar(@sorted_ids)-1) {
                print FH "".$ip_info{$this_ip_pair}{id_ts}[$i].", ".$sorted_ids[$i]."\n";
            }
            # print FH join("\n", @{$ip_info{$this_ip_pair}{id_ts}})."\n";
            close FH;
            my $escape_figure_dir = $figure_dir;
            $escape_figure_dir =~ s/\//\\\//g;
            my $escape_figure_data_dir = $figure_data_dir;
            $escape_figure_data_dir =~ s/\//\\\//g;
            system("sed 's/FILENAME/normal.$file_id.$this_ip_pair.ids.txt/;s/FIGDIR/$escape_figure_dir/;s/DATADIR/$escape_figure_data_dir/' plot_id.plot.mother > plot_id.plot");
            system("gnuplot plot_id.plot");
            system("rm plot_id.plot");


            ##  b) entropy, throughput, pkt, ttl
            open FH, "> $figure_data_dir/normal.$file_id.$this_ip_pair.ts.txt" or die $!;
            my $max_tput = max(@{$ip_info{$this_ip_pair}{tput_ts}});
            my $max_pkt = max(@{$ip_info{$this_ip_pair}{pkt_ts}});
            my $max_entropy = max(@{$ip_info{$this_ip_pair}{entropy_ts}});
            foreach my $i (0 .. scalar(@{$ip_info{$this_ip_pair}{ttl_ts}})-1) {
                print FH "".$ip_info{$this_ip_pair}{ttl_ts}[$i].", ".($ip_info{$this_ip_pair}{tput_ts}[$i] / $max_tput).", ".($ip_info{$this_ip_pair}{pkt_ts}[$i] / $max_pkt).", ";
                
                if($max_entropy != 0) {
                    print FH "".($ip_info{$this_ip_pair}{entropy_ts}[$i] / $max_entropy)."\n";
                }
                else {
                    print FH "0\n";
                }
                
            }
            close FH;
            system("sed 's/FILENAME/normal.$file_id.$this_ip_pair.ts.txt/;s/FIGDIR/$escape_figure_dir/;s/DATADIR/$escape_figure_data_dir/' plot_ts.plot.mother > plot_ts.plot");
            system("gnuplot plot_ts.plot");
            system("rm plot_ts.plot");

        }


        #####
        ## DEBUG
        #####
        if($DEBUG0) {
            die "not possible\n" if($this_flow_tether_tput > 0 or $this_flow_tether_pkt > 0);
        }

    }
}


#####
## output
print "TTL:\n";
print "  number of tethering flows: ".(keys %{$tether_info{ttl}{ip_pair}})." / $total_flow_cnt = ".((keys %{$tether_info{ttl}{ip_pair}}) / $total_flow_cnt)."\n";
print "  number of tethering pkts: ".($tether_info{ttl}{pkt_cnt})." / $total_pkt_cnt = ".(($tether_info{ttl}{pkt_cnt}) / $total_pkt_cnt)."\n";
print "  number of tethering traffic: ".($tether_info{ttl}{pkt_byte})." / $total_pkt_byte = ".(($tether_info{ttl}{pkt_byte}) / $total_pkt_byte)."\n";


my $avg_intra_ratio_tput = 0;
$avg_intra_ratio_tput += $_ for @{$tether_info{ttl}{intra_ratio_tput}};
$avg_intra_ratio_tput /= scalar(@{$tether_info{ttl}{intra_ratio_tput}});

my $avg_intra_ratio_pkt = 0;
$avg_intra_ratio_pkt += $_ for @{$tether_info{ttl}{intra_ratio_pkt}};
$avg_intra_ratio_pkt /= scalar(@{$tether_info{ttl}{intra_ratio_pkt}});

my $avg_intra_ratio_entropy = 0;
$avg_intra_ratio_entropy += $_ for @{$tether_info{ttl}{intra_ratio_entropy}};
$avg_intra_ratio_entropy /= scalar(@{$tether_info{ttl}{intra_ratio_entropy}});

print "  intra flow, the ratio of tethered to non-tethered period:\n";
print "    tput: $avg_intra_ratio_tput\n";
print "    pkt: $avg_intra_ratio_pkt\n";
print "    entrooy: $avg_intra_ratio_entropy\n";


my $avg_tether_flow_tput = 0;
$avg_tether_flow_tput += $_ for @{$tether_info{ttl}{tether_tput}};
$avg_tether_flow_tput /= scalar(@{$tether_info{ttl}{tether_tput}});

my $avg_tether_flow_pkt = 0;
$avg_tether_flow_pkt += $_ for @{$tether_info{ttl}{tether_pkt}};
$avg_tether_flow_pkt /= scalar(@{$tether_info{ttl}{tether_pkt}});

my $avg_tether_flow_entropy = 0;
$avg_tether_flow_entropy += $_ for @{$tether_info{ttl}{tether_entropy}};
$avg_tether_flow_entropy /= scalar(@{$tether_info{ttl}{tether_entropy}});

my $avg_normal_flow_tput = 0;
$avg_normal_flow_tput += $_ for @{$tether_info{ttl}{normal_tput}};
$avg_normal_flow_tput /= scalar(@{$tether_info{ttl}{normal_tput}});

my $avg_normal_flow_pkt = 0;
$avg_normal_flow_pkt += $_ for @{$tether_info{ttl}{normal_pkt}};
$avg_normal_flow_pkt /= scalar(@{$tether_info{ttl}{normal_pkt}});

my $avg_normal_flow_entropy = 0;
$avg_normal_flow_entropy += $_ for @{$tether_info{ttl}{normal_entropy}};
$avg_normal_flow_entropy /= scalar(@{$tether_info{ttl}{normal_entropy}});

$tether_info{ttl}{inter_ratio_tput} = $avg_tether_flow_tput / $avg_normal_flow_tput;
$tether_info{ttl}{inter_ratio_pkt} = $avg_tether_flow_pkt / $avg_normal_flow_pkt;
$tether_info{ttl}{inter_ratio_entropy} = $avg_tether_flow_entropy / $avg_normal_flow_entropy;

print "  inter flow, the ratio of tethered to non-tethered flow:\n";
print "    tput: ".$tether_info{ttl}{inter_ratio_tput}."\n";
print "    pkt: ".$tether_info{ttl}{inter_ratio_pkt}."\n";
print "    entrooy: ".$tether_info{ttl}{inter_ratio_entropy}."\n";


1;


#####
## functions
