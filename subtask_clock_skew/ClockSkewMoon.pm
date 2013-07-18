package ClockSkewMoon;

use strict;

sub intersection {
    my ($m1, $b1, $m2, $b2) = @_;

    if($m1 == $m2) {
        print join(",", ($m1, $b1, $m2, $b2))."\n";
    }
    return ( ($b2-$b1) / ($m1-$m2), ($m1*$b2 - $m2*$b1) / ($m1 - $m2) );
}



sub clock_skew_moon {
    my ($d_ref, $ts_ref) = @_;
    my ($alpha, $beta);

    unshift(@$d_ref, 0);
    unshift(@$ts_ref, 0);

    my @n = (0, 1, 2);
    my $k  = 2;

    foreach my $i (3 .. scalar(@$d_ref)-1) {
        my $j;
        for($j = $k; $j >= 2; $j --) {

            ## skip the same slope?
            # next if($ts_ref->[$i] == $ts_ref->[$n[$j]] or $ts_ref->[$n[$j]] == $ts_ref->[$n[$j-1]]);


            my ($x1, $y1) = intersection($ts_ref->[$i], -$d_ref->[$i], 
                                         $ts_ref->[$n[$j]], -$d_ref->[$n[$j]]);
            my ($x2, $y2) = intersection($ts_ref->[$n[$j]], -$d_ref->[$n[$j]], 
                                         $ts_ref->[$n[$j-1]], -$d_ref->[$n[$j-1]]);

            last if($x1 > $x2);
        }
        $k = $j + 1;
        $n[$k] = $i;
    }

    my $opt = 0;
    for my $tmp (@$ts_ref) {
        $opt += $tmp;
    }
    $opt /= (scalar(@$ts_ref)-1);

    foreach my $i (1 .. $k-1) {
        if($ts_ref->[$n[$i]] < $opt and $opt < $ts_ref->[$n[$i+1]]) {
            
            ## skip the same slope?
            # next if($ts_ref->[$n[$i]] == $ts_ref->[$n[$i+1]]);


            my ($x, $y) = intersection($ts_ref->[$n[$i]], -$d_ref->[$n[$i]], 
                                       $ts_ref->[$n[$i+1]], -$d_ref->[$n[$i+1]]);
            $alpha = $x;
            $beta  = $y;
            last;
        }
    }

    return ($alpha, $beta);
}


sub clock_skew_moon_v1 {
    my ($d_ref, $ts_ref) = @_;
    my ($alpha, $beta);

    my @n = (1, 2);
    my $k  = 2;

    foreach my $i (3 .. scalar(@$d_ref)) {
        my $j;
        for($j = $k; $j >= 2; $j --) {
            my ($x1, $y1) = intersection($ts_ref->[$i-1], -$d_ref->[$i-1], 
                                         $ts_ref->[$n[$j-1] - 1], -$d_ref->[$n[$j-1] - 1]);
            my ($x2, $y2) = intersection($ts_ref->[$n[$j-1] - 1], -$d_ref->[$n[$j-1] - 1], 
                                         $ts_ref->[$n[$j-1] - 2], -$d_ref->[$n[$j-1] - 2]);

            last if($x1 > $x2);
        }
        $k = $j + 1;
        $n[$k-1] = $i;
    }

    my $opt = 0;
    for my $tmp (@$ts_ref) {
        $opt += $tmp;
    }
    $opt /= scalar(@$ts_ref);

    foreach my $i (1 .. $k-1) {
        if($ts_ref->[$n[$i-1] - 1] < $opt and $opt < $ts_ref->[$n[$i] - 1]) {
            my ($x, $y) = intersection($ts_ref->[$n[$i-1] - 1], -$d_ref->[$n[$i-1] - 1], 
                                       $ts_ref->[$n[$i] - 1], -$d_ref->[$n[$i] - 1]);
            $alpha = $x;
            $beta  = $y;
            last;
        }
    }

    return ($alpha, $beta);
}


1;