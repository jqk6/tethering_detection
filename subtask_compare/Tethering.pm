
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
    
    my $boot_span_threshold = 3;
    my $gr_bt_type = 0;
    my $flow_pktnum_threshold = 30;
    my $flow_dur_threshold = 5;
    my @freqs = (2, 10, 100, 128, 200, 1000);

    return _est_freq_boottime_enumeration($rx_time_ref, $tx_ts_ref, \@freqs, $boot_span_threshold, $flow_pktnum_threshold, $flow_dur_threshold);
}

sub est_freq_boottime_enumeration2 {
    my ($rx_time_ref, $tx_ts_ref) = @_;
    
    my $boot_span_threshold = 3;
    my $gr_bt_type = 0;
    my $flow_pktnum_threshold = 30;
    my $flow_dur_threshold = 5;
    my @freqs = (1 .. 1000);

    return _est_freq_boottime_enumeration($rx_time_ref, $tx_ts_ref, \@freqs, $boot_span_threshold, $flow_pktnum_threshold, $flow_dur_threshold);
}

#######
## _est_freq_boottime_enumeration
##   estimate the clock frequency and the boot time using enumeration
##
## @input rx_time_ref           : the array reference of the receiving times
## @input tx_ts_ref             : the array reference of the Timestamp
## @input freqs_ref             : the array reference of the possible frequencies
## @input gr_bt_type            : 0 to use estimate frequency; 1 to use 100Hz
## @input boot_span_threshold   : the threshold to determine if the boot time is stable
## @input flow_pktnum_threshold : the threshold to determine if the flow is used
## @input flow_dur_threshold    : the threshold to determine if the flow is used
##
## @output freq      : -1 if cannot find a frequency which make the differenc of boot times smaller than the threshold
## @output boot_time : the average boot time if freq != -1
##
sub _est_freq_boottime_enumeration {
    my ($rx_time_ref, $tx_ts_ref, $freqs_ref, $gr_bt_type, $boot_span_threshold, $flow_pktnum_threshold, $flow_dur_threshold) = @_;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));

    ## check flow pkt num
    return (-1, -1) if(scalar(@$rx_time_ref) < $flow_pktnum_threshold);
    ## check flow duration
    return (-1, -1) if(($rx_time_ref->[-1] - $rx_time_ref->[0]) < $flow_dur_threshold);


    my $min_span = $boot_span_threshold + 1;
    my $min_span_freq = 0;
    my $min_span_boot_time = 0;
    my $group_boot_time = -1;
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
        if($this_freq == 100 && $gr_bt_type == 1) {
            $group_boot_time = MyUtil::average(\@this_boot_times);
        }
        else {
            $group_boot_time = $min_span_boot_time;
        }
    }
    if($group_boot_time < 0 && $gr_bt_type == 1) {
        my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@$tx_ts_ref)-1) {
            push(@this_boot_times, $rx_time_ref->[$ind] - $tx_ts_ref->[$ind] / 100);
        }
        $group_boot_time = MyUtil::average(\@this_boot_times);
    }
    if($min_span < $boot_span_threshold){
        return ($min_span_freq, $group_boot_time);
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
        # next if($this_agent =~ /VM670/);

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


#######
## _check_timestamp_continuity
##   check if the timestamps are continuous number
##
## @input rx_time_ref           : the array reference of the receiving times
## @input tx_ts_ref             : the array reference of the Timestamp
## @input freq_thresh           : the largest possible frequency
## @input min_thresh            : the largest possible interval if two packets are close
##
## @output continuity           : 0: Timestamp are not continuous; 1: otherwise
##
sub _check_timestamp_continuity {
    my ($rx_time_ref, $tx_ts_ref, $freq_thresh, $min_thresh) = @_;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));

    my $num_disorder = 0;
    my $pre_rx_time = $rx_time_ref->[0];
    my $pre_tx_time = $tx_ts_ref->[0];
    foreach my $ind (1 .. scalar(@$tx_ts_ref)-1) {
        my $rx_time = $rx_time_ref->[$ind];
        my $tx_time = $tx_ts_ref->[$ind];

        ## wrap around or disordering
        if($tx_time < $pre_tx_time) {
            $num_disorder ++;
            $pre_rx_time = $rx_time;
            $pre_tx_time = $tx_time;
        }
        ## the interval between continuous Timestamp should be less than a threshold
        else {
            return 0 if( ($tx_time - $pre_tx_time) > ($rx_time - $pre_rx_time) * $freq_thresh and 
                         ($tx_time - $pre_tx_time) > $min_thresh);
        }
    }

    return 1;
}
1;
