package TetheringFeatures;

use strict;
use POSIX qw/floor/;
use List::Util qw(sum max min);
use MyUtil;


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
## @output has_feature  : 0=not tethering; 1=tethering
##
sub ttl_num_feature {
    my ($ttl_ref) = @_;
    my $cnt_threshold = 1;
    my $has_feature = 0;

    if(scalar(@$ttl_ref) > $cnt_threshold) {
        $has_feature = 1;
    }
    else {
        $has_feature = 0;
    }

    return $has_feature;
}


#######
## 2. check_gap_ttl_num
##   Sometimes because of multi-path, even one client could have multiple TTLs. Just checking the number of TTLs might cause false positive. To prevent the problem, we observe that these TTLs from one client would be very close to each other. So this heuristic only count TTLs which is different by 5 or more.
##
## @input TTL_ref       : the array reference of TTLs
## @input gap_threshold : the minimal gap that different TTLs should have
##
## @output has_feature  : 0=not tethering; 1=tethering
##
sub ttl_num_gap_feature {
    my ($ttl_ref, $gap_threshold) = @_;
    my $cnt_threshold = 1;
    my $has_feature = 0;
    my $num_ttl = 0;

    ## calculate # of TTLs with the large enough gap
    my $prev_ttl = -10;
    foreach my $this_ttl (sort {$a <=> $b} (@$ttl_ref)) {
        $num_ttl ++ if($this_ttl - $prev_ttl > $gap_threshold);
        
        $prev_ttl = $this_ttl;
    }
    
    ## check if tethering
    if($num_ttl > $cnt_threshold) {
        $has_feature = 1;
    }
    else {
        $has_feature = 0;
    }

    return $has_feature;
}

sub ttl_num_gap_num {
    my ($ttl_ref, $gap_threshold) = @_;
    my $cnt_threshold = 1;
    my $has_feature = 0;
    my $num_ttl = 0;

    ## calculate # of TTLs with the large enough gap
    my $prev_ttl = -10;
    foreach my $this_ttl (sort {$a <=> $b} (@$ttl_ref)) {
        $num_ttl ++ if($this_ttl - $prev_ttl > $gap_threshold);
        
        $prev_ttl = $this_ttl;
    }
    
    return $num_ttl;
}


########################################################
## IP ID
## 
########################################################
sub ip_id_monotonicity_feature {
    my $DEBUG0 = 0;
    my $DEBUG1 = 0;

    my ($ip_ids_ref, $ip_ids_flow_ref) = @_;

    my $feature;
    
    my $thresh_mono_pkts = 0.9;
    my $thresh_mono_flows = 0.9;
    my $thresh_part_mono_flows = 0.4;
    
    my ($ratio_monotonic_pkts, $ratio_monotonic_flows) = ip_id_monotonicity_ratio($ip_ids_ref, $ip_ids_flow_ref);
    print "    $ratio_monotonic_pkts, $ratio_monotonic_flows\n" if($DEBUG1);


    #####
    ## not enough packets
    #####
    if($ratio_monotonic_pkts < 0) {
        $feature = -1;
        return $feature;
    }

    #####
    ## monotonic for all pkts
    #####
    if($ratio_monotonic_pkts > $thresh_mono_pkts) {
        $feature = 0;
        return $feature;
    }

    #####
    ## not enough flows -> random
    #####
    if($ratio_monotonic_flows < 0) {
        $feature = 3;
        return $feature;
    }
    

    #####
    ## monotonic for each flows
    #####
    if($ratio_monotonic_flows > $thresh_mono_flows) {
        $feature = 1;
        return $feature;
    }


    #####
    ## not monotonic
    #####
    if($ratio_monotonic_flows < 1-$thresh_mono_flows) {
        $feature = 3;
        return $feature;
    }


    #####
    ## monotonic for part of flows
    #####
    # if($ratio_monotonic_flows > $thresh_part_mono_flows) {
    #     $feature = 2;
    #     return $feature;
    # }
    $feature = 2;
    return $feature;


    # die "unknow IP ID state: $ratio_monotonic_pkts, $ratio_monotonic_flows";
}


sub ip_id_monotonicity_ratio {
    my $DEBUG0 = 0;
    my $DEBUG1 = 0;

    my $thresh = 0.02;

    my ($ip_ids_ref, $ip_ids_flow_ref) = @_;
    
    my $ratio_monotonic_pkts = 0;
    my $ratio_monotonic_flows = 0;
    
    my $num_disorder = 0;

    
    #####
    ## monotonic pkts
    #####
    my $prev = -1;
    my $cnt = 0;
    my @ip_id_diffs = ();
    foreach my $this_id (@$ip_ids_ref) {
        $cnt ++;

        if($prev == -1 or $this_id >= $prev) {
            ## ok here
            push(@ip_id_diffs, $this_id - $prev);
        }
        else {
            ## not increasing..
            $num_disorder ++;
        }

        $prev = $this_id;
    }
    print "      disorder pkts= $num_disorder/$cnt\n" if($DEBUG1);
    print "      IP ID increased by = ".MyUtil::average(\@ip_id_diffs).", stdev = ".MyUtil::stdev(\@ip_id_diffs)."\n" if($DEBUG1);
    return (-1, -1) if($cnt < 10);

    $ratio_monotonic_pkts = ($cnt - $num_disorder) / $cnt;
    
    
    #####
    ## monotonic for each flows
    #####
    my $num_disorder_flow = 0;
    my $num_flow = 0;
    foreach my $flow (keys %{ $ip_ids_flow_ref->{CONN} }) {
        print "    $flow => " if($DEBUG0);
        
        my $prev = -1;
        my $cnt = 0;
        @ip_id_diffs = ();
        $num_disorder = 0;

        foreach my $this_id (@{ $ip_ids_flow_ref->{CONN}{$flow}{IP_ID} }) {
            $cnt ++;

            if($prev == -1 or $this_id >= $prev) {
                ## ok here
                push(@ip_id_diffs, $this_id - $prev);
            }
            else {
                ## not increasing..
                $num_disorder ++;
            }

            $prev = $this_id;
        }
        next if($cnt < 10);
        $num_flow ++;

        # $num_disorder -- if($num_disorder > 1);  ## XXX: trick
        my $ratio = $num_disorder / $cnt;
        print "      flow $num_flow: disorder=$num_disorder/$cnt=$ratio\n" if($DEBUG1);
        print "          increased by = ".MyUtil::average(\@ip_id_diffs).", stdev = ".MyUtil::stdev(\@ip_id_diffs)."\n" if($DEBUG1);
        print " $ratio / $cnt\n" if($DEBUG0);

        $num_disorder_flow ++ if($ratio > $thresh);
    }
    print "    #flows=$num_flow\n" if($DEBUG1);
    
    if($num_flow == 0) {
        return ($ratio_monotonic_pkts, -1);
    }
    else {
        $ratio_monotonic_flows = ($num_flow - $num_disorder_flow) / $num_flow;
        return ($ratio_monotonic_pkts, $ratio_monotonic_flows);
    }
}



########################################################
## TCP Window Scale Heuristics
## @input win_scales_ref: a reference of a hash table from Win Scale to the number of its occurance 
##
## @output if_tether: 0=not tethering; 1=tethering
## @output os: a reference of a hash table of detected OSs
##
########################################################
sub win_scale_feature {
    my $DEBUG0 = 0;
    my $DEBUG1 = 1;

    my ($win_scales_ref) = @_;
    my %os;
    my $thresh = 0.01;

    my ($ratio_16, $ratio_64, $ratio_256) = win_scale_ratio($win_scales_ref);


    if($ratio_16 > $thresh) {
        $os{APPLE} = 1;
        return 0;
    }
    elsif($ratio_64 > $thresh) {
        $os{ANDROID} = 1;
        return 1;
    }
    elsif($ratio_256 > $thresh) {
        $os{WINDOWS} = 1;
        return 2;
    }

    return -1;
}  


sub win_scale_ratio {
    my $DEBUG0 = 0;
    my $DEBUG1 = 1;

    my ($win_scales_ref) = @_;
    my ($ratio_16, $ratio_64, $ratio_256) = (0, 0, 0);
    
    my $sum = 0;
    foreach my $this_win (keys %$win_scales_ref) {
        $sum += $win_scales_ref->{$this_win};
    }

    foreach my $this_win (keys %$win_scales_ref) {
        my $ratio = $win_scales_ref->{$this_win} / $sum;
        print "    $this_win: $ratio\n" if($DEBUG0);

        if($this_win == 16) {
            ## iOS
            $ratio_16 = $ratio;
        }
        elsif($this_win == 64) {
            ## Android
            $ratio_64 = $ratio;
        }
        elsif($this_win == 256) {
            ## Windows
            $ratio_256 = $ratio;
        }
    }

    return ($ratio_16, $ratio_64, $ratio_256);
}  


########################################################
## TCP Timestamp Option Heuristics
## @input opt_kind_ref: a reference of a hash table from TCP kinds to the number of its occurance 
##
## @output os: a reference of a hash table of detected OSs
##
########################################################
sub tcp_timestamp_option_feature {
    my ($opt_kind_ref, $opt_kind_flow_ref, $per_flow_thresh) = @_;

    my $pkt_ratio_thresh = 0.3;

    my ($ratio_has_ts_pkts, $ratio_has_ts_flows) = tcp_timestamp_option_ratio($opt_kind_ref, $opt_kind_flow_ref, $per_flow_thresh);

    if($ratio_has_ts_pkts > $pkt_ratio_thresh) {
        ## not Windows
        return 1;
    }
    else {
        ## Windows
        return 0;
    }

}
sub tcp_timestamp_option_ratio {
    my $DEBUG0 = 0;
    my $DEBUG1 = 1;


    my ($opt_kind_ref, $opt_kind_flow_ref, $per_flow_thresh) = @_;
    # my %os;
    # my $all_flow_thresh = 0.2;
    # my $per_flow_thresh = 0.1;
    my $ts_kind = 8;

    my $ratio_has_ts_pkts = 0;
    my $ratio_has_ts_flows = 0;


    #####
    ## all pkts
    #####
    my $sum = 0;
    foreach my $this_opt (keys %$opt_kind_ref) {
        $sum += $opt_kind_ref->{$this_opt};
        print "    $this_opt: ".$opt_kind_ref->{$this_opt}." / $sum\n"  if($DEBUG0);
    }
    return (0, 0) if($sum < 10);

    $ratio_has_ts_pkts = $opt_kind_ref->{$ts_kind} / $sum;
    print "    timestamp: $ratio_has_ts_pkts\n" if($DEBUG0);

    
    #####
    ## each flow
    #####
    my $num_flow = 0;
    my $num_has_ts_flows = 0;
    foreach my $flow (keys %{ $opt_kind_flow_ref->{CONN} }) {
        my $num_pkt = 0;
        my $num_ts_pkt = 0;
        foreach my $this_opt (keys %{ $opt_kind_flow_ref->{CONN}{$flow}{OPT_KIND} }) {
            $num_pkt += $opt_kind_flow_ref->{CONN}{$flow}{OPT_KIND}{$this_opt};
            $num_ts_pkt = $opt_kind_flow_ref->{CONN}{$flow}{OPT_KIND}{$this_opt} if($this_opt == 8);
        }

        next if($num_pkt < 10);
        $num_flow ++;

        my $ratio = $num_ts_pkt/$num_pkt;
        print "    flow timestamp: $ratio\n" if($DEBUG0);
        
        if($ratio > $per_flow_thresh) {
            $num_has_ts_flows ++;
        }
    }

    if($num_flow > 0) {
        $ratio_has_ts_flows = $num_has_ts_flows / $num_flow;
    }

    return ($ratio_has_ts_pkts, $ratio_has_ts_flows);
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
sub timestamp_monotonicity_feature {
    my ($rx_time_ref, $tx_ts_ref, $freq_thresh) = @_;

    my $disorder_thresh = 0.1;
    my $disorder_pkts_thresh = 5;
    my $large_gap_thresh = 0.1;
    my $large_gap_pkts_thresh = 5;

    my ($ratio_disorder, $ratio_large_gap) = timestamp_monotonicity_ratio($rx_time_ref, $tx_ts_ref, $freq_thresh);


    if($ratio_disorder == -1) {
        ## not enough packet
        return -1;
    }
    elsif($ratio_disorder > $disorder_thresh or $ratio_disorder*scalar(@$rx_time_ref) > $disorder_pkts_thresh) {
        ## tethering: many disorder TS
        return 0;
    }
    elsif($ratio_large_gap > $large_gap_thresh or $ratio_large_gap*scalar(@$rx_time_ref) > $large_gap_pkts_thresh) {
        ## might be tethering: not many disorder, but some large gaps
        return 1;
    }
    else {
        ## TS is monotonic: not tethering
        return 2;
    }
}

sub timestamp_monotonicity_ratio {
    my ($rx_time_ref, $tx_ts_ref, $freq_thresh) = @_;

    my $DEBUG1 = 0;
    
    die "tx and rx array size do not match\n" if(scalar(@$tx_ts_ref) != scalar(@$rx_time_ref));

    my $num_pkts = scalar(@$tx_ts_ref);
    my $num_wrap = 0;
    my $num_disorder = 0;
    my $num_large_gap = 0;
    my $if_tether = 0;

    my ($ratio_disorder, $ratio_large_gap) = (0, 0);


    my $pre_rx_time = $rx_time_ref->[0];
    my $pre_tx_time = $tx_ts_ref->[0];
    foreach my $ind (1 .. $num_pkts-1) {
        my $rx_time = $rx_time_ref->[$ind];
        my $tx_time = $tx_ts_ref->[$ind];

        # print "$tx_time, ";

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
    # print "\n";

    ## print rx time for DEBUG
    # foreach my $ind (1 .. $num_pkts-1) {
    #     my $rx_time = $rx_time_ref->[$ind];
    #     my $tx_time = $tx_ts_ref->[$ind];
    #     print "$rx_time, ";
    # }
    # print "\n";

    if($num_pkts < 5) {
        return (-1, -1);
    }
    $ratio_disorder = $num_disorder / $num_pkts;
    print "    ratio disorder = $ratio_disorder = $num_disorder / $num_pkts\n" if($DEBUG1);


    if($num_pkts < 20) {
        return ($ratio_disorder, -1);
    }
    $ratio_large_gap = $num_large_gap / $num_pkts;
    print "    ratio_large_gap = $ratio_large_gap = $num_large_gap / $num_pkts\n" if($DEBUG1);

    return ($ratio_disorder, $ratio_large_gap);
}


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
sub flow_frequency_first_last_stdev_feature {
    my ($flows_ref, $stdev_thresh) = @_;

    # my $span_thresh = 60*200;

    my $freq_stdev = flow_frequency_first_last_stdev($flows_ref);
    print "    freq_stdev=$freq_stdev\n";

    if($freq_stdev < 0) {
        ## not enough flow
        return -1;
    }
    elsif($freq_stdev > $stdev_thresh) {
        ## different freq --> tethering
        return 1;
    }
    else {
        ## same freq
        return 0;
    }
}

sub flow_frequency_first_last_stdev {
    my ($flows_ref) = @_;

    my @freqs;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet. 
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_first_last(\@rx_time, \@tx_time);
        next if($this_freq < 0);

        print "    flow: freq=$this_freq (len=".($rx_time[-1]-$rx_time[0])."s)\n";

        push(@freqs, $this_freq);
    }

    if(scalar(@freqs) <= 1) {
        ## only one flow, cannot compare
        return -1;
    }
    else {
        my $freq_stdev = MyUtil::stdev(\@freqs);
        my $span = max(@freqs) - min(@freqs);
        print "        stdev=$freq_stdev\n";
        print "        span=$span\n";
        return $freq_stdev;
    }
}

sub flow_frequency_first_last_span {
    my ($flows_ref) = @_;

    my @freqs;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet. 
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_first_last(\@rx_time, \@tx_time);
        next if($this_freq < 0);

        # print "    flow: freq=$this_freq (len=".($rx_time[-1]-$rx_time[0])."s)\n";

        push(@freqs, $this_freq);
    }

    if(scalar(@freqs) <= 1) {
        ## only one flow, cannot compare
        return -1;
    }
    else {
        my $freq_stdev = MyUtil::stdev(\@freqs);
        my $span = max(@freqs) - min(@freqs);
        # print "        stdev=$freq_stdev\n";
        # print "        span=$span\n";
        return $span;
    }
}

######
## 2. check_flow_frequency_first_last_enumeration
##    First calculate the clock frequency by using the first and the last packet. 
##    Then find the closest one from the given list.
##    If clock frequency of flows are different, then it's tethering
######
sub flow_frequency_first_last_enumeration {
    my ($flows_ref, $freqs_ref) = @_;

    my %freqs;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet,
    ##   and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_first_last_enumeration(\@rx_time, \@tx_time, $freqs_ref);
        next if($this_freq < 0);

        $freqs{$this_freq} = 1;
    }

    return scalar(keys %freqs);
}


######
## 3. check_flow_frequency_median_span
##    Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds. 
##    And then use the median as the clock frequency.
##    If the max and min clock frequency of flows > freq_span_threshold, then it's tethering
######
sub flow_frequency_median_span {
    my ($flows_ref, $rx_time_gap) = @_;

    my @freqs;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   and then use the median as the clock frequency.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_median(\@rx_time, \@tx_time, $rx_time_gap);
        next if($this_freq < 0);

        push(@freqs, $this_freq);
    }

    my $span = max(@freqs) - min(@freqs);
    return $span;
}

######
## 4. check_flow_frequency_median_enumeration
##    First calculate the clock frequency by using the first packet and those after 5 seconds,
##    and use the median as the clock frequency.
##    Then find the closest one from the given list.
##    If clock frequency of flows are different, then it's tethering
######
sub flow_frequency_median_enumeration {
    my ($flows_ref, $freqs_ref, $rx_time_gap) = @_;

    my %freqs;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   use the median as the clock frequency, and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_median_enumeration(\@rx_time, \@tx_time, $freqs_ref, $rx_time_gap);
        next if($this_freq < 0);

        $freqs{$this_freq} = 1;
    }

    return scalar(keys %freqs);
}

######
## 5. check_flow_frequency_enumeration_boot_span
##    Given a list of possible frequencies, calculate boot time using these frequencies.
##    Then select the frequency which gives has smallest boot time span
##    If clock frequency of flows are different, then it's tethering
######
sub flow_frequency_enumeration_boot_span {
    my ($flows_ref, $freqs_ref, $boot_time_span_thresh) = @_;

    my %freqs;
    my $if_tether = 0;

    ## Given a list of possible frequencies, calculate boot time using these frequencies,
    ##   and select the frequency which gives has smallest boot time span
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        my $this_freq = calculate_flow_frequency_enumeration_boot_span(\@rx_time, \@tx_time, $freqs_ref, $boot_time_span_thresh);
        next if($this_freq < 0);

        $freqs{$this_freq} = 1;
    }

    return scalar(keys %freqs);
}


###############################################
## frequency of flows are stable
#####
sub flow_frequency_stable_feature {
    my ($flows_ref, $rx_time_gap) = @_;

    my $stdev_thresh = 5;
    my $ratio_stable_thresh = 0.4;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   and then use the median as the clock frequency.
    my $num_flows = 0;
    my $num_stable_flows = 0;
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        my @freqs = ();
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };
        next if(@rx_time < 5);  ## too small number of packet

        ## calculate the clock frequency by using the consecutive packet.
        foreach my $ind (1 .. scalar(@rx_time)-1) {
            next if($rx_time[$ind] - $rx_time[0] < $rx_time_gap);

            my $this_freq = ($tx_time[$ind] - $tx_time[0]) / ($rx_time[$ind] - $rx_time[0]);
            push(@freqs, $this_freq);
        }

        if(@freqs > 20) {
            $num_flows ++;
            my $freq_stdev = MyUtil::stdev(\@freqs);
            print "    flow $num_flows: stdev=$freq_stdev, num calculated freq=".scalar(@freqs)."\n";
            
            if($freq_stdev < $stdev_thresh) {
                $num_stable_flows ++;
            }
        }
    }

    if($num_flows == 0) {
        ## no flow has enough pkts
        return -1;
    }
    else {
        my $stable_ratio = $num_stable_flows / $num_flows;
        print "    stable ratio = $num_stable_flows / $num_flows = $stable_ratio\n";
        
        if($stable_ratio > $ratio_stable_thresh) {
            ## stable
            return 1;
        }
        else {
            ## unstable
            return 0;
        }
    }
}


sub flow_frequency_stable_stdev {
    my ($flows_ref, $rx_time_gap) = @_;

    my $num_flows = 0;
    my $num_stable_flows = 0;

    my @freqs = ();
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };
        next if(@rx_time < 5);  ## too small number of packet

        ## calculate the clock frequency by using the consecutive packet.
        foreach my $ind (1 .. scalar(@rx_time)-1) {
            next if($rx_time[$ind] - $rx_time[0] < $rx_time_gap);

            my $this_freq = ($tx_time[$ind] - $tx_time[0]) / ($rx_time[$ind] - $rx_time[0]);
            push(@freqs, $this_freq);
        }
    }

    if(@freqs < 20) {
        return (-1, -1);
    } 
    else {
        my $mean_freq = MyUtil::median(\@freqs);
        my $stdev_freq = MyUtil::stdev(\@freqs);
        # print "    mean freq = $mean_freq\n";
        return ($mean_freq, $stdev_freq);
    }
}

sub boot_time_median_enumeration_stdev {
    my ($flows_ref, $freqs_ref, $rx_time_gap) = @_;

    my @boot_times;
    my $if_tether = 0;

    my ($this_freq, $tmp) = flow_frequency_stable_stdev($flows_ref, $rx_time_gap);

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   use the median as the clock frequency, and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

        my @rx_time = @{ $flows_ref->{CONN}{$this_flow}{RX_TIME} };
        my @tx_time = @{ $flows_ref->{CONN}{$this_flow}{TX_TIME} };

        
        ## use the frequency to calculate the boot time.
        # my @this_boot_times = ();
        foreach my $ind (0 .. scalar(@rx_time)-1) {
            my $this_boot_time = $rx_time[$ind] - $tx_time[$ind] / $this_freq;
            # push(@this_boot_times, $this_boot_time);
            push(@boot_times, $this_boot_time);
        }
        # next if(@this_boot_times == 0);

        # push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    # my $span = max(@boot_times) - min(@boot_times);
    if(@boot_times < 20) {
        return -1;
    } 
    else {
        return MyUtil::stdev(\@boot_times);
    }
}
########################################################

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
sub boot_time_first_last_stdev_feature {
    my ($flows_ref, $stdev_thresh) = @_;

    my $bt_stdev = boot_time_first_last_stdev($flows_ref);
    print "    bt_stdev=$bt_stdev\n";

    if($bt_stdev < 0) {
        ## not enough flow
        return -1;
    }
    elsif($bt_stdev > $stdev_thresh) {
        ## different boot time --> tethering
        return 1;
    }
    else {
        ## same freq
        return 0;
    }
}

sub boot_time_first_last_stdev {
    my ($flows_ref) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet. 
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

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

        print "    flow: bt=".(MyUtil::median(\@this_boot_times))." (len=".($rx_time[-1]-$rx_time[0])."s)\n";

        push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    if(@boot_times <= 1) {
        ## not enough flows
        return -1;
    }
    else {
        my $span = max(@boot_times) - min(@boot_times);
        my $bt_stdev = MyUtil::stdev(\@boot_times);
        print "    bt_stdev=$bt_stdev\n";

        return $bt_stdev;
    }
    
}

sub boot_time_first_last_span {
    my ($flows_ref) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet. 
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

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

        # print "    flow: bt=".(MyUtil::median(\@this_boot_times))." (len=".($rx_time[-1]-$rx_time[0])."s)\n";

        push(@boot_times, MyUtil::median(\@this_boot_times));
    }

    if(@boot_times <= 1) {
        ## not enough flows
        return -1;
    }
    else {
        my $span = max(@boot_times) - min(@boot_times);
        my $bt_stdev = MyUtil::stdev(\@boot_times);
        # print "    bt_stdev=$bt_stdev\n";

        return $span;
    }
    
}

######
## 2. check_boot_time_first_last_enumeration
##    First calculate the clock frequency by using the first and the last packet. 
##    Then find the closest one from the given list.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub boot_time_first_last_enumeration {
    my ($flows_ref, $freqs_ref) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## calculate the clock frequency by using the first and the last packet,
    ##   and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

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

    my $span = max(@boot_times) - min(@boot_times);
    return $span;
}

######
## 3. check_boot_time_median_span
##    Calculate the clock frequency by using the first packet and those after 5 seconds. 
##    Then use the median as the clock frequency.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub boot_time_median_span {
    my ($flows_ref, $rx_time_gap, $boot_time_span_thresh) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   and then use the median as the clock frequency.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

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

    my $span = max(@boot_times) - min(@boot_times);
    return $span;
}

######
## 4. check_boot_time_median_enumeration
##    First calculate the clock frequency by using the first packet and those after 5 seconds,
##    and use the median as the clock frequency.
##    Then find the closest one from the given list.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub boot_time_median_enumeration {
    my ($flows_ref, $freqs_ref, $rx_time_gap) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## Calculate the clock frequency by using the first packet and those after 5 (rx_time_gap) seconds,
    ##   use the median as the clock frequency, and find the closest one from the given list.
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

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

    my $span = max(@boot_times) - min(@boot_times);
    return $span;
}

######
## 5. check_boot_time_enumeration_boot_span
##    Given a list of possible frequencies, calculate boot time using these frequencies.
##    Then select the frequency which gives has smallest boot time span.
##    Then use the frequency to calculate the boot time.
##    If the span of boot times of all flows > boot_time_span_thresh, then it's tethering
######
sub boot_time_enumeration_boot_span {
    my ($flows_ref, $freqs_ref, $boot_time_span_thresh) = @_;

    my @boot_times;
    my $if_tether = 0;

    ## Given a list of possible frequencies, calculate boot time using these frequencies,
    ##   and select the frequency which gives has smallest boot time span
    foreach my $this_flow (keys %{ $flows_ref->{CONN} }) {
        next unless(exists $flows_ref->{CONN}{$this_flow}{RX_TIME});

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

    my $span = max(@boot_times) - min(@boot_times);
    return $span;
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
    my $flow_len_thresh = 5;

    ## calculate the clock frequency by using the first and the last packet. 
    if($rx_time_ref->[-1] - $rx_time_ref->[0] > $flow_len_thresh) {
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
1;