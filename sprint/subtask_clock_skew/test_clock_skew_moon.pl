#!/bin/perl

use strict;
use ClockSkewMoon;


#####
## intersection
#####
print "test intersection\n";
my @line1 = (-2, 2);
my @line2 = (0, 1);
my ($x, $y) = ClockSkewMoon::intersection(@line1, @line2);
print "should intersect at (0.5, 1): result = ($x, $y)\n";

print "\n";

#####
## clock skew moon
#####
print "\ntest clock skew moon\n";
my @ts = (0, 1, 2, 3, 4);
my @d  = (0, 1, 2, 3, 4);

print "ts: ".join(", ", @ts)."\n";
print "d: ".join(", ", @d)."\n";

# my ($alpha, $beta) = ClockSkewMoon::clock_skew_moon_v1(\@d, \@ts);
my ($alpha, $beta) = ClockSkewMoon::clock_skew_moon(\@d, \@ts);
print $alpha.", ".$beta."\n";
