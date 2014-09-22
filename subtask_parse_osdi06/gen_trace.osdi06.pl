#!/bin/perl

##########################################
## Author: Yi-Chao Chen
## 2014.04.14 @ UT Austin
##
##
## - input:
##
## - output:
##
## - e.g.
##    perl gen_trace.osdi06.pl osdi06.filter 1 0.2 0 1
##
##########################################

use strict;
use POSIX;
use List::Util qw(first max maxstr min minstr reduce shuffle sum);
use lib "../utils";
use lib "/u/yichao/utils/perl";

use Tethering;
use randperm;


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
my $TICK = 500;


#############
# Variables
#############
my $input_dir  = "../processed_data/subtask_parse_osdi06/tshark";
my $output_dir = "../processed_data/subtask_parse_osdi06/gen_trace";
my $filename;
my $ratio_dup;
my $ratio_host;
my $bt_diff;
my $seed;

my %ip_info = ();


#############
# check input
#############
if(@ARGV != 5) {
    print "wrong number of input: ".@ARGV."\n";
    exit;
}
$filename   = $ARGV[0];
$ratio_dup  = $ARGV[1] + 0;
$ratio_host = $ARGV[2] + 0;
$bt_diff    = $ARGV[3] + 0;
$seed       = $ARGV[4] + 0;
srand $seed;


#############
# Main starts
#############
# my @ind  = randperm::randperm(1,10);
# print join(",", @ind)."\n";
# exit;


#############
## read the filename
#############
print "read the filename\n" if($DEBUG2);

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
    $cnt += 0; $rcv_time += 0; $id += 0; $ttl += 0; $tsval += 0; $tsecr += 0; $wsscale += 0; $inflight += 0;
    print "  src=$src, dst=$dst, id=$id, ttl=$ttl, ts=$tsval, win scale=$wsscale, opt=$opt_kind, UA=$ua, flight bytes=$inflight\n" if($DEBUG0);

    $ip_info{SRC}{$src}{ORIG_IP} = $src;
    $ip_info{SRC}{$src}{LINE}{$_} = 1;
    $ip_info{RCV_TIME}{$rcv_time}{LINE}{$_} = 1;
}
close FH;

my @orig_ips = keys %{ $ip_info{SRC} };
print "  # orig IPs: ".scalar(@orig_ips)."\n";


#############
## duplicate IPs
#############
print "duplicate IPs\n" if($DEBUG2);

my $dup_ip_ind = 0;

foreach my $di (1 .. $ratio_dup-1) {
    foreach my $this_ip (@orig_ips) {
        my $new_ip = "1.2.3.$dup_ip_ind";
        $ip_info{SRC}{$new_ip}{ORIG_IP} = $this_ip;
        $dup_ip_ind ++;

        foreach my $this_line (keys %{ $ip_info{SRC}{$this_ip}{LINE} }) {
            my ($cnt, $rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $_);
            $cnt += 0; $rcv_time += 0; $id += 0; $ttl += 0; $tsval += 0; $tsecr += 0; $wsscale += 0; $inflight += 0;
            print "  src=$src, dst=$dst, id=$id, ttl=$ttl, ts=$tsval, win scale=$wsscale, opt=$opt_kind, UA=$ua, flight bytes=$inflight\n" if($DEBUG0);

            my $new_line = join("|", ($cnt, $rcv_time, $new_ip, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));

            $ip_info{SRC}{$new_ip}{LINE}{$new_line} = 1;
            $ip_info{RCV_TIME}{$rcv_time}{LINE}{$new_line} = 1;
        }
    }
}

my @ips = keys %{ $ip_info{SRC} };
my $num_host = floor(scalar(@ips) * $ratio_host);
print "  # IPs after duplication: ".scalar(@ips)."\n";
print "  # host: $num_host\n";



#############
## gen dup IPs
#############
print "gen dup IPs\n" if($DEBUG2);

my @tmp       = randperm::randperm(0, @ips-1);
my @teth_inds = @tmp[0..$num_host-1];
my @teth_ips  = @ips[@teth_inds];
my @host_inds = @tmp[$num_host..2*$num_host-1];
my @host_ips  = @ips[@host_inds];

my %teth_info = ();
my %host_info = ();
foreach my $ii (0 .. @teth_ips-1) {
    my $this_ip = $teth_ips[$ii];

    $teth_info{SRC}{$this_ip}{HOST} = $host_ips[$ii];
    $host_info{SRC}{$host_ips[$ii]}{DUP} = $this_ip;
}


my @other_inds = @tmp[2*$num_host..@ips-1];
my @other_ips  = @ips[@other_inds];
my %other_info = ();

if($DEBUG0) {
    print "  # tethered = ".scalar(@teth_ips)."\n";
    print "    ".join("\n    ", @teth_ips)."\n";
    print "  # host = ".scalar(@host_ips)."\n";
    print "    ".join("\n    ", @host_ips)."\n";
    print "  # rest = ".scalar(@other_ips)."\n";
}


#############
## reset IP and rcv_time
#############
print "reset IP and boot time\n" if($DEBUG2);

my %new_ip_info = ();
# foreach my $this_ip (keys %{ $ip_info{SRC} }) {
#     foreach my $this_line (keys %{ $ip_info{SRC}{$this_ip}{LINE} }) {
foreach my $this_rt (sort {$a <=> $b} (keys %{ $ip_info{RCV_TIME} })) {
    foreach my $this_line (keys %{ $ip_info{RCV_TIME}{$this_rt}{LINE} }) {
        my ($cnt, $rcv_time, $src_list, $dst_list, $sport_list, $dport_list, $id_list, $ttl_list, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight) = split(/\|/, $this_line);
        my @tmp = split(/,/, $src_list); my $src = $tmp[-1];
        @tmp = split(/,/, $dst_list); my $dst = $tmp[-1];
        @tmp = split(/,/, $sport_list); my $sport = $tmp[-1];
        @tmp = split(/,/, $dport_list); my $dport = $tmp[-1];
        @tmp = split(/,/, $id_list); my $id = $tmp[-1];
        @tmp = split(/,/, $ttl_list); my $ttl = $tmp[-1];
        $cnt += 0; $rcv_time += 0; $id += 0; $ttl += 0; $tsval += 0; $tsecr += 0; $wsscale += 0; $inflight += 0;
        print "  src=$src, dst=$dst, id=$id, ttl=$ttl, ts=$tsval, win scale=$wsscale, opt=$opt_kind, UA=$ua, flight bytes=$inflight\n" if($DEBUG0);


        if(exists $teth_info{SRC}{$src}) {
            ## Tethered IPs
            my $new_ip = $teth_info{SRC}{$src}{HOST};

            my $new_rcv_time = $bt_diff;
            if(exists $teth_info{SRC}{$src}{FIRST_RCV_TIME}) {
                my $rcv_diff = $rcv_time - $teth_info{SRC}{$src}{FIRST_RCV_TIME};
                $new_rcv_time += $rcv_diff;

                if($rcv_diff < 0) {
                    foreach my $l (keys %{ $ip_info{SRC}{$src}{LINE} }) {
                        print "  $l\n";
                    }
                    die "rcv diff < 0";
                }
            }
            else {
                $teth_info{SRC}{$src}{FIRST_RCV_TIME} = $rcv_time;
            }

            my $new_line = join("|", ($cnt, $new_rcv_time, $new_ip, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
            $new_ip_info{RCV_TIME}{$new_rcv_time}{LINE}{$new_line} = 1;
        }
        elsif(exists $host_info{SRC}{$src}) {
            ## Host IPs
            my $new_rcv_time = 0;
            if(exists $host_info{SRC}{$src}{FIRST_RCV_TIME}) {
                my $rcv_diff = $rcv_time - $host_info{SRC}{$src}{FIRST_RCV_TIME};
                $new_rcv_time += $rcv_diff;

                if($rcv_diff < 0) {
                    foreach my $l (keys %{ $ip_info{SRC}{$src}{LINE} }) {
                        print "  $l\n";
                    }
                    die "rcv diff < 0";
                }
            }
            else {
                $host_info{SRC}{$src}{FIRST_RCV_TIME} = $rcv_time;
            }

            my $new_line = join("|", ($cnt, $new_rcv_time, $src, $dst, $sport, $dport, $id, $ttl, $tsval, $tsecr, $wsscale, $opt_kind, $ua, $inflight));
            $new_ip_info{RCV_TIME}{$new_rcv_time}{LINE}{$new_line} = 1;
        }
        else {
            ## normal IPs
            $new_ip_info{RCV_TIME}{$rcv_time}{LINE}{$this_line} = 1;
        }
    }
}



#############
## output the new file
#############
print "output the new file\n" if($DEBUG2);

my $output_filename = "$filename.dup$ratio_dup.host$ratio_host.bt$bt_diff.s$seed";
if(-e "$output_dir/$output_filename.txt.bz2") {
    my $cmd = "rm \"$output_dir/$output_filename.txt.bz2\"";
    `$cmd`;
}

open FH_OUT, "> $output_dir/$output_filename.txt" or die $!;
foreach my $this_rt (sort {$a <=> $b} (keys %{ $new_ip_info{RCV_TIME} })) {
    foreach my $this_line (keys %{ $new_ip_info{RCV_TIME}{$this_rt}{LINE} }) {
        print FH_OUT $this_line."\n";
    }
}
close FH_OUT;


#############
## output ground truth
#############
print "output ground truth\n" if($DEBUG2);

my $gt_filename = "$output_filename.gt";
if(-e "$output_dir/$gt_filename.txt.bz2") {
    my $cmd = "rm \"$output_dir/$gt_filename.txt.bz2\"";
    `$cmd`;
}

open FH_GT, "> $output_dir/$gt_filename.txt" or die $!;
# print FH_GT join(", 1\n", @host_ips).", 1\n" if(scalar(@host_ips) > 0);
# print FH_GT join(", 0\n", @other_ips).", 0\n";
foreach my $this_ip (keys %{ $host_info{SRC} }) {
    my $dup_ip = $host_info{SRC}{$this_ip}{DUP};
    print FH_GT "$this_ip, 1, ".$ip_info{SRC}{$this_ip}{ORIG_IP}.", $dup_ip, ".$ip_info{SRC}{$dup_ip}{ORIG_IP}."\n";
}
foreach my $this_ip (@other_ips) {
    print FH_GT "$this_ip, 0, ".$ip_info{SRC}{$this_ip}{ORIG_IP}.", X, X\n";
}
close FH_GT;


#############
## compress the output file
#############
print "compress the output file\n" if($DEBUG2);

my $cmd = "bzip2 \"$output_dir/$output_filename.txt\"";
`$cmd`;
$cmd = "bzip2 \"$output_dir/$gt_filename.txt\"";
`$cmd`;
