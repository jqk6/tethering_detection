
package Tethering;

use strict;
use POSIX qw/floor/;
use List::Util qw(sum max min);


#######
## est_freq_boottime_enumeration1
##   estimate the clock frequency and the boot time using enumeration
##
## @input rx_time_ref: the array reference of the receiving times
## @input tx_ts_ref  : the array reference of the Timestamp
##
## @output freq      : -1 if cannot find a frequency which make the differenc of boot times smaller than the threshold
## @output boot_time : the average boot time if freq != -1
##
sub est_freq_boottime_enumeration1 {
    my ($rx_time_ref, $tx_ts_ref) = @_;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));
    my $threshold = 3;
    my @freqs = (2, 10, 100, 128, 200, 1000);

    return _est_freq_boottime_enumeration($rx_time_ref, $tx_ts_ref, \@freqs, $threshold);
}

sub est_freq_boottime_enumeration2 {
    my ($rx_time_ref, $tx_ts_ref) = @_;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));
    my $threshold = 3;
    my @freqs = (1 .. 1000);

    return _est_freq_boottime_enumeration($rx_time_ref, $tx_ts_ref, \@freqs, $threshold);
}

sub est_freq_boottime_enumeration3 {
    my ($rx_time_ref, $tx_ts_ref, $threshold) = @_;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));
    my @freqs = (2, 10, 100, 128, 200, 1000);

    return _est_freq_boottime_enumeration($rx_time_ref, $tx_ts_ref, \@freqs, $threshold);
}

#######
## _est_freq_boottime_enumeration
##   estimate the clock frequency and the boot time using enumeration
##
## @input rx_time_ref: the array reference of the receiving times
## @input tx_ts_ref  : the array reference of the Timestamp
## @input freqs_ref  : the array reference of the possible frequencies
## @input threshold  : the threshold to determine if the boot time is stable
##
## @output freq      : -1 if cannot find a frequency which make the differenc of boot times smaller than the threshold
## @output boot_time : the average boot time if freq != -1
##
sub _est_freq_boottime_enumeration {
    my ($rx_time_ref, $tx_ts_ref, $freqs_ref, $threshold) = @_;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));


    my $min_span = $threshold + 1;
    my $min_span_freq = 0;
    my $min_span_boot_time = 0;
    foreach my $this_freq (@$freqs_ref) {
        my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@$tx_ts_ref)-1) {
            push(@this_boot_times, $rx_time_ref->[$ind] - $tx_ts_ref->[$ind] / $this_freq);
        }
        
        my $this_boot_time_span = abs( max(@this_boot_times) - min(@this_boot_times) );
        if($this_boot_time_span < $min_span) {
            $min_span = $this_boot_time_span;
            $min_span_freq = $this_freq;
            $min_span_boot_time = MyUtil::average(\@this_boot_times);
        }
    }
    if($min_span < $threshold){
        return ($min_span_freq, $min_span_boot_time);
    }
    else {
        return (-1, -1);
    }
}



#####
## identify_os
##   Identify the OS from User Agent strings
##
## @input user_agent_ref: the array reference of User Agent strings
##
## @output os: the array of identified OSs
##
sub identify_os {
    my ($user_agent_ref) = @_;

    my @os_keywords = ("Windows", "Microsoft", "Android", "Mac OS X", "iPhone OS", "uTorrentMac", "Ubuntu", "Xbox");
    my @os_names    = ("Windows", "Windows",   "Android", "Apple"   , "Apple",     "Apple",       "Linux",  "Xbox");

    return _identify_os($user_agent_ref, \@os_keywords, \@os_names);
}


#####
## _identify_os
##   Identify the OS from User Agent strings
##
## @input user_agent_ref: the array reference of User Agent strings
## @input os_keyword_ref: the array reference of OS keywords
## @input os_name_ref   : the array reference of OS names
##
## @output os: the array of identified OSs
##
sub _identify_os {
    my ($user_agent_ref, $os_keyword_ref, $os_name_ref) = @_;

    my %os_hash = ();
    foreach my $this_agent (@$user_agent_ref) {
        foreach my $ind (0 .. scalar(@$os_keyword_ref)-1) {
            my $os_keyword = $os_keyword_ref->[$ind];
            my $os         = $os_name_ref->[$ind];

            if($this_agent =~ /$os_keyword/i) {
                $os_hash{$os} = 1;
                last;
            }
        }
    }

    return (keys %os_hash);
}

1;
