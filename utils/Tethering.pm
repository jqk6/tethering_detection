
package Tethering;

use strict;
use POSIX qw/floor/;
use List::Util qw(sum max min);
use MyUtil;


########################################################
## Frequency Heuristics
## 1. check_flow_frequency_first_last_span
##    Calculate the clock frequency by using the first and the last packet. 
##    If the max and min clock frequency of flows > freq_span_threshold, then it's tethering
##
## 2. check_flow_frequency_first_last_enumeration
##    First calculate the clock frequency by using the first and the last packet. 
##    Then find the closest one from the given list.
##    If clock frequency of flows are different, then it's tethering
##
## 3. check_flow_frequency_median_span
##    Calculate the clock frequency by using the first packet and those after 5 seconds. 
##    And then use the median as the clock frequency.
##    If the max and min clock frequency of flows > freq_span_threshold, then it's tethering
##
## 4. check_flow_frequency_median_enumeration
##    First calculate the clock frequency by using the first packet and those after 5 seconds,
##    and use the median as the clock frequency.
##    Then find the closest one from the given list.
##    If clock frequency of flows are different, then it's tethering
##
## 5. check_flow_frequency_enumeration_boot_span
##    Given a list of possible frequencies, calculate boot time using these frequencies.
##    Then select the frequency which gives has smallest boot time span
##    If clock frequency of flows are different, then it's tethering
##
########################################################

######
## 1. check_flow_frequency_first_last_span
##    Calculate the clock frequency by using the first and the last packet. 
##    If the max and min clock frequency of flows > freq_span_threshold, then it's tethering
######
sub check_flow_frequency_first_last_span {
    my ($flows_ref, $freq_span_threshold) = @_;

    my @freqs;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet. 
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_first_last(\@rx_time, \@tx_time);
        next if($this_freq < 0);

        push(@freqs, $this_freq);
    }

    ## If the max and min clock frequency of flows > freq_span_threshold, then it's tethering
    if(max(@freqs) - min(@freqs) > $freq_span_threshold) {
        $if_tether = 1;
    }

    return $if_tether;
}

######
## 2. check_flow_frequency_first_last_enumeration
##    First calculate the clock frequency by using the first and the last packet. 
##    Then find the closest one from the given list.
##    If clock frequency of flows are different, then it's tethering
######
sub check_flow_frequency_first_last_enumeration {
    my ($flows_ref, $freqs_ref) = @_;

    my %freqs;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet,
    ##   and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_first_last_enumeration(\@rx_time, \@tx_time, $freqs_ref);
        next if($this_freq < 0);

        $freqs{$this_freq} = 1;
    }

    ## If clock frequency of flows are different, then it's tethering
    if(scalar(keys %freqs) > 1) {
        $if_tether = 1;
    }

    return $if_tether;
}


######
## 3. check_flow_frequency_median_span
##    Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds. 
##    And then use the median as the clock frequency.
##    If the max and min clock frequency of flows > freq_span_threshold, then it's tethering
######
sub check_flow_frequency_median_span {
    my ($flows_ref, $rx_time_gap, $freq_span_threshold) = @_;

    my @freqs;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   and then use the median as the clock frequency.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_median(\@rx_time, \@tx_time, $rx_time_gap);
        next if($this_freq < 0);

        push(@freqs, $this_freq);
    }

    ## If the max and min clock frequency of flows > freq_span_threshold, then it's tethering
    if(max(@freqs) - min(@freqs) > $freq_span_threshold) {
        $if_tether = 1;
    }

    return $if_tether;
}

######
## 4. check_flow_frequency_median_enumeration
##    First calculate the clock frequency by using the first packet and those after 5 seconds,
##    and use the median as the clock frequency.
##    Then find the closest one from the given list.
##    If clock frequency of flows are different, then it's tethering
######
sub check_flow_frequency_median_enumeration {
    my ($flows_ref, $freqs_ref, $rx_time_gap) = @_;

    my %freqs;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   use the median as the clock frequency, and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_median_enumeration(\@rx_time, \@tx_time, $freqs_ref, $rx_time_gap);
        next if($this_freq < 0);

        $freqs{$this_freq} = 1;
    }

    ## If clock frequency of flows are different, then it's tethering
    if(scalar(keys %freqs) > 1) {
        $if_tether = 1;
    }

    return $if_tether;
}

######
## 5. check_flow_frequency_enumeration_boot_span
##    Given a list of possible frequencies, calculate boot time using these frequencies.
##    Then select the frequency which gives has smallest boot time span
##    If clock frequency of flows are different, then it's tethering
######
sub check_flow_frequency_enumeration_boot_span {
    my ($flows_ref, $freqs_ref, $boot_time_span_thresh) = @_;

    my %freqs;
    my $if_tether = 0;

    ## Given a list of possible frequencies, calculate boot time using these frequencies,
    ##   and select the frequency which gives has smallest boot time span
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_enumeration_boot_span(\@rx_time, \@tx_time, $freqs_ref, $boot_time_span_thresh);
        next if($this_freq < 0);

        $freqs{$this_freq} = 1;
    }

    ## If clock frequency of flows are different, then it's tethering
    if(scalar(keys %freqs) > 1) {
        $if_tether = 1;
    }

    return $if_tether;
}


########################################################
## Boot Time Heuristics
## 1. check_boot_time_first_last_span
##    Calculate the clock frequency by using the first and the last packet. 
##    And then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
##
## 2. check_boot_time_first_last_enumeration
##    First calculate the clock frequency by using the first and the last packet. 
##    Then find the closest one from the given list.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
##
## 3. check_boot_time_median_span
##    Calculate the clock frequency by using the first packet and those after 5 seconds. 
##    Then use the median as the clock frequency.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
##
## 4. check_boot_time_median_enumeration
##    First calculate the clock frequency by using the first packet and those after 5 seconds,
##    and use the median as the clock frequency.
##    Then find the closest one from the given list.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
##
## 5. check_boot_time_enumeration_boot_span
##    Given a list of possible frequencies, calculate boot time using these frequencies.
##    Then select the frequency which gives has smallest boot time span.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
########################################################

######
## 1. check_boot_time_first_last_span
##    Calculate the clock frequency by using the first and the last packet. 
##    And then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub check_boot_time_first_last_span {
    my ($flows_ref, $boot_time_span_thresh) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet. 
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_first_last(\@rx_time, \@tx_time);
        next if($this_freq <= 0);


        ## use the frequency to calculate the boot time.
        my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@rx_time)-1) {
            my $this_boot_time = $rx_time[$ind] - $tx_time[$ind] / $this_freq;
            push(@this_boot_times, $this_boot_time);
        }
        next if(@this_boot_times == 0);

        push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    ## If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
    if(max(@boot_times) - min(@boot_times) > $boot_time_span_thresh) {
        $if_tether = 1;
    }

    return $if_tether;
}

######
## 2. check_boot_time_first_last_enumeration
##    First calculate the clock frequency by using the first and the last packet. 
##    Then find the closest one from the given list.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub check_boot_time_first_last_enumeration {
    my ($flows_ref, $freqs_ref, $boot_time_span_thresh) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet,
    ##   and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_first_last_enumeration(\@rx_time, \@tx_time, $freqs_ref);
        next if($this_freq <= 0);

        
        ## use the frequency to calculate the boot time.
        my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@rx_time)-1) {
            my $this_boot_time = $rx_time[$ind] - $tx_time[$ind] / $this_freq;
            push(@this_boot_times, $this_boot_time);
        }
        next if(@this_boot_times == 0);

        push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    ## If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
    if(max(@boot_times) - min(@boot_times) > $boot_time_span_thresh) {
        $if_tether = 1;
    }

    return $if_tether;
}

######
## 3. check_boot_time_median_span
##    Calculate the clock frequency by using the first packet and those after 5 seconds. 
##    Then use the median as the clock frequency.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub check_boot_time_median_span {
    my ($flows_ref, $rx_time_gap, $boot_time_span_thresh) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   and then use the median as the clock frequency.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_median(\@rx_time, \@tx_time, $rx_time_gap);
        next if($this_freq <= 0);

        
        ## use the frequency to calculate the boot time.
        my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@rx_time)-1) {
            my $this_boot_time = $rx_time[$ind] - $tx_time[$ind] / $this_freq;
            push(@this_boot_times, $this_boot_time);
        }
        next if(@this_boot_times == 0);

        push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    ## If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
    if(max(@boot_times) - min(@boot_times) > $boot_time_span_thresh) {
        $if_tether = 1;
    }

    return $if_tether;
}

######
## 4. check_boot_time_median_enumeration
##    First calculate the clock frequency by using the first packet and those after 5 seconds,
##    and use the median as the clock frequency.
##    Then find the closest one from the given list.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub check_boot_time_median_enumeration {
    my ($flows_ref, $freqs_ref, $rx_time_gap, $boot_time_span_thresh) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   use the median as the clock frequency, and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_median_enumeration(\@rx_time, \@tx_time, $freqs_ref, $rx_time_gap);
        next if($this_freq <= 0);

        
        ## use the frequency to calculate the boot time.
        my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@rx_time)-1) {
            my $this_boot_time = $rx_time[$ind] - $tx_time[$ind] / $this_freq;
            push(@this_boot_times, $this_boot_time);
        }
        next if(@this_boot_times == 0);

        push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    ## If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
    if(max(@boot_times) - min(@boot_times) > $boot_time_span_thresh) {
        $if_tether = 1;
    }

    return $if_tether;
}

######
## 5. check_boot_time_enumeration_boot_span
##    Given a list of possible frequencies, calculate boot time using these frequencies.
##    Then select the frequency which gives has smallest boot time span.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub check_boot_time_enumeration_boot_span {
    my ($flows_ref, $freqs_ref, $boot_time_span_thresh) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## Given a list of possible frequencies, calculate boot time using these frequencies,
    ##   and select the frequency which gives has smallest boot time span
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_enumeration_boot_span(\@rx_time, \@tx_time, $freqs_ref, $boot_time_span_thresh);
        next if($this_freq <= 0);

        
        ## use the frequency to calculate the boot time.
        my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@rx_time)-1) {
            my $this_boot_time = $rx_time[$ind] - $tx_time[$ind] / $this_freq;
            push(@this_boot_times, $this_boot_time);
        }
        next if(@this_boot_times == 0);

        push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    ## If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
    if(max(@boot_times) - min(@boot_times) > $boot_time_span_thresh) {
        $if_tether = 1;
    }

    return $if_tether;
}


########################################################
## Helper: calculate frequency
########################################################
######
## 1. calculate_flow_frequency_first_last
##    Calculate the clock frequency by using the first and the last packet. 
######
sub calculate_flow_frequency_first_last {
    my ($rx_time_ref, $tx_time_ref) = @_;

    my $freq = -1;

    ## calculate the clock frequency by using the first and the last packet. 
    if($rx_time_ref->[0] != $rx_time_ref->[-1]) {
        $freq = ($tx_time_ref->[-1] - $tx_time_ref->[0]) / ($rx_time_ref->[-1] - $rx_time_ref->[0]);
    }

    return $freq;
}


######
## 2. calculate_flow_frequency_first_last_enumeration
##    First calculate the clock frequency by using the first and the last packet. 
##    Then find the closest one from the given list.
######
sub calculate_flow_frequency_first_last_enumeration {
    my ($rx_time_ref, $tx_time_ref, $freqs_ref) = @_;

    my $freq = -1;

    ## calculate the clock frequency by using the first and the last packet. 
    if($rx_time_ref->[0] != $rx_time_ref->[-1]) {
        $freq = ($tx_time_ref->[-1] - $tx_time_ref->[0]) / ($rx_time_ref->[-1] - $rx_time_ref->[0]);
    }

    ## find the closest one from the given list.
    if($freq > 0) {
        my $best_freq = -10000;
        foreach my $this_freq (@$freqs_ref) {
            if( abs($freq - $this_freq) < abs($best_freq - $this_freq) or $best_freq < 0 ) {
                $best_freq = $this_freq;
            }
        }
        $freq = $best_freq;
    }
    
    return $freq;
}

######
## 3. calculate_flow_frequency_median
##    Calculate the clock frequency by using the first packet and those after 5 ($rx_time_gap) seconds. 
##    And then use the median as the clock frequency.
######
sub calculate_flow_frequency_median {
    my ($rx_time_ref, $tx_time_ref, $rx_time_gap) = @_;

    my @freqs;
    my $freq = -1;

    ## calculate the clock frequency by using the first and the last packet.
    foreach my $ind (1 .. scalar(@$rx_time_ref)-1) {
        next if($rx_time_ref->[$ind] - $rx_time_ref->[0] < $rx_time_gap);

        my $this_freq = ($tx_time_ref->[$ind] - $tx_time_ref->[0]) / ($rx_time_ref->[$ind] - $rx_time_ref->[0]);
        push(@freqs, $this_freq);
    }

    ## use the median as the clock frequency.
    if(@freqs > 0) {
        $freq = MyUtil::median(\@freqs);
    }

    return $freq;
}

######
## 4. calculate_flow_frequency_median_enumeration
##    First calculate the clock frequency by using the first packet and those after 5 seconds,
##    and use the median as the clock frequency.
##    Then find the closest one from the given list.
######
sub calculate_flow_frequency_median_enumeration {
    my ($rx_time_ref, $tx_time_ref, $freqs_ref, $rx_time_gap) = @_;

    my @freqs;
    my $freq = -1;

    ## calculate the clock frequency by using the first and the last packet.
    foreach my $ind (1 .. scalar(@$rx_time_ref)-1) {
        next if($rx_time_ref->[$ind] - $rx_time_ref->[0] < $rx_time_gap);

        my $this_freq = ($tx_time_ref->[$ind] - $tx_time_ref->[0]) / ($rx_time_ref->[$ind] - $rx_time_ref->[0]);
        push(@freqs, $this_freq);
    }

    ## use the median as the clock frequency.
    if(@freqs > 0) {
        $freq = MyUtil::median(\@freqs);
    }

    ## find the closest one from the given list.
    if($freq > 0) {
        my $best_freq = -10000;
        foreach my $this_freq (@$freqs_ref) {
            if( abs($freq - $this_freq) < abs($best_freq - $this_freq) or $best_freq < 0 ) {
                $best_freq = $this_freq;
            }
        }
        $freq = $best_freq;
    }

    return $freq;
}

######
## 5. calculate_flow_frequency_enumeration_boot_span
##    Given a list of possible frequencies, calculate boot time using these frequencies.
##    Then select the frequency which gives has smallest boot time span
######
sub calculate_flow_frequency_enumeration_boot_span {
    my ($rx_time_ref, $tx_time_ref, $freqs_ref, $boot_time_span_thresh) = @_;

    my $freq = -1;
    my @boot_times;
    my $smallest_boot_span = -1;

    ## calculate boot time using these frequencies.
    foreach my $this_freq (@$freqs_ref) {
        foreach my $ind (0 .. scalar(@$rx_time_ref)-1) {
            my $this_boot_time = $rx_time_ref->[$ind] - $tx_time_ref->[$ind] / $this_freq;
            push(@boot_times, $this_boot_time);
        }
        next if(@boot_times == 0);

        ## select the frequency which gives has smallest boot time span
        my $this_boot_span = max(@boot_times) - min(@boot_times);
        if($this_boot_span < $smallest_boot_span or $smallest_boot_span < 0) {
            $smallest_boot_span = $this_boot_span;
            $freq = $this_freq;
        }
    }
    

    if($smallest_boot_span < 0 or $smallest_boot_span > $boot_time_span_thresh) {
        $freq = -1;
    }

    return $freq;
}


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
# sub est_freq_boottime_enumeration1 {
#     my ($rx_time_ref, $tx_ts_ref) = @_;
    
#     my $boot_span_threshold = 3;
#     my $gr_bt_type = 0;
#     my $flow_pktnum_threshold = 30;
#     my $flow_dur_threshold = 5;
#     my @freqs = (2, 10, 100, 128, 200, 1000);

#     return _est_freq_boottime_enumeration($rx_time_ref, $tx_ts_ref, \@freqs, $boot_span_threshold, $flow_pktnum_threshold, $flow_dur_threshold);
# }

# sub est_freq_boottime_enumeration2 {
#     my ($rx_time_ref, $tx_ts_ref) = @_;
    
#     my $boot_span_threshold = 3;
#     my $gr_bt_type = 0;
#     my $flow_pktnum_threshold = 30;
#     my $flow_dur_threshold = 5;
#     my @freqs = (1 .. 1000);

#     return _est_freq_boottime_enumeration($rx_time_ref, $tx_ts_ref, \@freqs, $boot_span_threshold, $flow_pktnum_threshold, $flow_dur_threshold);
# }

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
# sub _est_freq_boottime_enumeration {
#     my ($rx_time_ref, $tx_ts_ref, $freqs_ref, $gr_bt_type, $boot_span_threshold, $flow_pktnum_threshold, $flow_dur_threshold) = @_;
    
#     die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));

#     ## check flow pkt num
#     return (-1, -1) if(scalar(@$rx_time_ref) < $flow_pktnum_threshold);
#     ## check flow duration
#     return (-1, -1) if(($rx_time_ref->[-1] - $rx_time_ref->[0]) < $flow_dur_threshold);


#     my $min_span = $boot_span_threshold + 1;
#     my $min_span_freq = 0;
#     my $min_span_boot_time = 0;
#     my $group_boot_time = -1;
#     foreach my $this_freq (@$freqs_ref) {
#         my @this_boot_times = ();
#         foreach my $ind (0 .. scalar(@$tx_ts_ref)-1) {
#             push(@this_boot_times, $rx_time_ref->[$ind] - $tx_ts_ref->[$ind] / $this_freq);
#         }

#         my $this_boot_time_span = abs( max(@this_boot_times) - min(@this_boot_times) );
#         if($this_boot_time_span < $min_span) {
#             $min_span = $this_boot_time_span;
#             $min_span_freq = $this_freq;
#             $min_span_boot_time = MyUtil::average(\@this_boot_times);
#         }
#         if($this_freq == 100 && $gr_bt_type == 1) {
#             $group_boot_time = MyUtil::average(\@this_boot_times);
#         }
#         else {
#             $group_boot_time = $min_span_boot_time;
#         }
#     }
#     if($group_boot_time < 0 && $gr_bt_type == 1) {
#         my @this_boot_times = ();
#         foreach my $ind (0 .. scalar(@$tx_ts_ref)-1) {
#             push(@this_boot_times, $rx_time_ref->[$ind] - $tx_ts_ref->[$ind] / 100);
#         }
#         $group_boot_time = MyUtil::average(\@this_boot_times);
#     }
#     if($min_span < $boot_span_threshold){
#         return ($min_span_freq, $group_boot_time);
#     }
#     else {
#         return (-1, -1);
#     }
# }


########################################################
## User Agent Heuristics
########################################################

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


########################################################
## Timestamp Monotonicity Heuristic
########################################################

#######
## check_timestamp_monotonicity
##   check if the timestamps are continuous number
##
## @input rx_time_ref           : the array reference of the receiving times
## @input tx_ts_ref             : the array reference of the Timestamp
## @input freq_thresh           : the largest possible frequency
## @input tolerate_wrap         : number of wrap to tolerate
## @input tolerate_disorder     : number of disorder to tolerate
## @input tolerate_gap          : number of large gap to tolerate
##
## @output continuity           : 0: Timestamp are not continuous; 1: otherwise
##
sub check_timestamp_monotonicity {
    my ($rx_time_ref, $tx_ts_ref, $freq_thresh, 
        $tolerate_wrap, $tolerate_disorder, $tolerate_gap) = @_;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));

    my $num_wrap = 0;
    my $num_disorder = 0;
    my $num_large_gap = 0;
    my $if_tether = 0;


    my $pre_rx_time = $rx_time_ref->[0];
    my $pre_tx_time = $tx_ts_ref->[0];
    foreach my $ind (1 .. scalar(@$tx_ts_ref)-1) {
        my $rx_time = $rx_time_ref->[$ind];
        my $tx_time = $tx_ts_ref->[$ind];

        ## wrap around
        if($pre_tx_time - $tx_time > 4000000000) {
            $num_wrap ++;
            $pre_rx_time = $rx_time;
            $pre_tx_time = $tx_time;
        }
        ## disordering
        elsif($tx_time < $pre_tx_time) {
            $num_disorder ++;
            $pre_rx_time = $rx_time;
            $pre_tx_time = $tx_time;
        }
        ## (Timestamp gap) should be less than (rx time gap * clock freq)
        elsif( ($tx_time - $pre_tx_time) > (($rx_time - $pre_rx_time) * $freq_thresh) ) {
            $num_large_gap ++;
            $pre_rx_time = $rx_time;
            $pre_tx_time = $tx_time;
        }
    }


    ## care about wrap??
    if($num_wrap > $tolerate_wrap) {
        $if_tether = 1;
    }
    ## tolerate number of disorder??
    if($num_disorder > $tolerate_disorder) {
        $if_tether = 1;
    }
    ## tolerate number of large TS gap??
    if($num_large_gap > $tolerate_gap) {
        $if_tether = 1;
    }


    return $if_tether;
}


########################################################
## TTL Heuristic
## 1. Number of TTLs > 1
## 2. Sometimes because of multi-path, even one client could have multiple TTLs. Just checking the number of TTLs might cause false positive. To prevent the problem, we observe that these TTLs from one client would be very close to each other. So this heuristic only count TTLs which is different by 5 or more.
########################################################

#######
## 1. check_ttl_num
##   check the number of TTL of this client. 
##   If # TTL > 1, then the client is tethering.
##   If # TTL == 1, then the client is not tethering.
##
## @input TTL_ref     : the array reference of TTLs
##
## @output if_tether  : 0=not tethering; 1=tethering
##
sub check_ttl_num {
    my ($ttl_ref) = @_;
    my $cnt_threshold = 1;
    my $if_tether = 0;

    if(scalar(@$ttl_ref) > $cnt_threshold) {
        $if_tether = 1;
    }
    else {
        $if_tether = 0;
    }

    return $if_tether;
}


#######
## 2. check_gap_ttl_num
##   Sometimes because of multi-path, even one client could have multiple TTLs. Just checking the number of TTLs might cause false positive. To prevent the problem, we observe that these TTLs from one client would be very close to each other. So this heuristic only count TTLs which is different by 5 or more.
##
## @input TTL_ref       : the array reference of TTLs
## @input gap_threshold : the minimal gap that different TTLs should have
##
## @output if_tether  : 0=not tethering; 1=tethering
##
sub check_gap_ttl_num {
    my ($ttl_ref, $gap_threshold) = @_;
    my $cnt_threshold = 1;
    my $if_tether = 0;
    my $num_ttl = 0;

    ## calculate # of TTLs with the large enough gap
    my $prev_ttl = -10;
    foreach my $this_ttl (sort {$a <=> $b} (@$ttl_ref)) {
        $num_ttl ++ if($this_ttl - $prev_ttl > $gap_threshold);
        
        $prev_ttl = $this_ttl;
    }
    
    ## check if tethering
    if($num_ttl > $cnt_threshold) {
        $if_tether = 1;
    }
    else {
        $if_tether = 0;
    }

    return $if_tether;
}


########################################################
## Frequency Stability
## not a detection method, just to check if the frequency is stable
## 1. check_freq_stability_enu
##    calculate frequency and see if it is far away from known freq
## 2. check_freq_stability_stdev
##    calculate frequency using each packet and see if the stdev is larger than a threshold
########################################################



########################################################
## IP ID
## not a detection method, just to check if IP ID monotonicity
########################################################
1;
