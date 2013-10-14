#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/20 @ Narus 
##
## A tool to show some example values of field in Narus vector
##
## - input: 
##      @file_id: -1 means any file
##      @field_name
##      @num_value: print out the specific number of values of the field. -1 means all values
##
##  e.g.
##      perl show_narus_vector_field.pl 0 ProtocolEventID 10
##
##################################################


use strict;


#####
## constant
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug



#####
## variables
my $input_dir = "/data/ychen/narus/bcp";

my $file_id;
my $field_name;
my $num_value;


#####
## check input
if(@ARGV != 3) {
    print "wrong number of input\n";
    exit;
}
$file_id    = $ARGV[0];
$field_name = $ARGV[1];
$num_value  = $ARGV[2];
print STDERR "file ID = $file_id, field = $field_name, # values = $num_value\n";


#####
## main starts here

## find file name
$file_id = 0 if($file_id == -1);
my $filename = `ls $input_dir/*-$file_id.bcp`;
chomp $filename;
die "id $file_id does not exists ($filename)\n" if(!(-e $filename));


## open narus vector 
open FH, "$filename" or die $!;
my $desc_id == -1;
my $field_ind;
my $cnt_found_values = 0;

while (my $line = <FH>) {
    print $line if($DEBUG1);
    
    ## find the field
    if($line =~ /Desc\[(\d+)\]=(.*\($field_name\)).*/) {
        print $line if($DEBUG1);
        print "> ".$1.": ".$2."\n" if($DEBUG1);

        $desc_id = $1 + 0;
        my @tmp_arr = split(/,/, $2);
        $field_ind = @tmp_arr;

        print "find this field in desc $desc_id at $field_ind column\n" if($DEBUG1);
    }


    ## find the values
    next if($desc_id == -1);
    if($line =~ /^\[$desc_id\]/) {
        print $line if($DEBUG2);

        my @tmp_arr = split(/\|/, $line);
        print $tmp_arr[$field_ind]."\n";
        $cnt_found_values ++;
        last if($cnt_found_values >= $num_value and $num_value != -1);
    }
}
close FH;

1;



#####
## functions
