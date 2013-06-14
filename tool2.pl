#!/bin/perl 

use strict;

my $MAX_TTL = 100;

open FH_SUMMARY, "> ./output/files.ttl.summary";


foreach my $file_id (49 .. 199, 0 .. 48) {
    my $file = "./output/file.$file_id.ttl.txt";
    if (!(-e $file)) {
        print "no such file: $file\n";
        next;
    }
    print `date`;
    print "  $file\n";

    my %ttl_info = ();
    open FH, $file or die $!;
    while(<FH>) {
        my ($ip_pair, $ttl_cnt, @ttls) = split(/, /, $_);
        $ttl_cnt += 0;
        die "wrong format\n" if($ttl_cnt != scalar(@ttls));
        die "need larger MAX_TTL: $ttl_cnt\n" if($ttl_cnt > $MAX_TTL);

        $ttl_info{$ttl_cnt} ++;
        # print $ttl_cnt.": ".$ttl_info{$ttl_cnt}."\n";
    }
    close FH;
    
    foreach my $ind (1 .. $MAX_TTL) {
        if(exists $ttl_info{$ind}) {
            print FH_SUMMARY "".$ttl_info{$ind}.", ";
        }
        else {
            print FH_SUMMARY "0, ";
        }
        
    }
    print FH_SUMMARY "\n";
}

close FH_SUMMARY;


