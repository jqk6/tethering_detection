
package MyBootTime;

##################################################
## Author: Yi-Chao Chen
## 2013/07/18 @ Narus
##
## My Boot Time fingerprintning method
##
##################################################

use strict;
use Data::Dumper;
use MyUtil;

#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 1; ## print for debug
my $DEBUG3 = 0; ## verbose for estimate_frequency
my $DEBUG4 = 1; ## verbose for estimate_boot_times


##################################################
## estimate_boot_times
##    Given a set of pakcets with TCP timestamp and receiving time,
##    this function returns an array contains the estimate boot times of all machines
##
## - input: %ip_info;
##   {TX_TIME}{sending time}{RX_TIME}{receiving time}
##
## - output
##
## - Parameters:
##   a) BOOT_TIME_SPAN: the max span allowed for a min and max estimated boot time
##   b) MIN_POINTS: the min number of points needed for a group
##
##
##
##################################################

sub estimate_boot_times {
    my $ip_info_ref = shift @_;
    my %ip_info = %$ip_info_ref;

    ## we don't know the frequencies of all machines, so here listing all possible frequencies that we need to try
    # my @possible_freq = (90 ... 1000);
    my @possible_freq;
    for (my $i = 100; $i <= 1000; $i += 5) {
        push(@possible_freq, $i);
    }


    my $BOOT_TIME_SPAN = 5;  ## the max span allowed for a min and max estimated boot time (in seconds)
    my $MIN_POINTS     = 50; ## the min number of points needed for a group

    my $num_devices = 0;
    my %group_info;          ## used to store group info


    foreach my $this_freq (@possible_freq) {
        print "freq=$this_freq\n" if($DEBUG4);

        my %this_boot_times;
        foreach my $this_tx_time (keys %{ $ip_info{TX_TIME} }) {
            foreach my $this_rx_time (keys %{ $ip_info{TX_TIME}{$this_tx_time}{RX_TIME} }) {
                my $this_boot_time = $this_rx_time - $this_tx_time / $this_freq;

                if($DEBUG1) {
                    print "t = $this_rx_time, T = $this_tx_time\n";
                    print "boot time ($this_freq) = $this_boot_time\n";
                }
                
                $this_boot_times{BOOT_TIME}{$this_boot_time}{TX_RX} = "$this_tx_time:$this_rx_time";
            }
        }


        ## clustering
        my @sorted_boot_times = sort {$a <=> $b} (keys %{ $this_boot_times{BOOT_TIME} });
        my $group_start_ind = -1;   ## The index of the start pkt of the current cluster.
        my $group_end_ind   = -1;   ## The index of the last  pkt of the current cluster.
        my %this_group_info = ();


        foreach my $ind (0 .. scalar(@sorted_boot_times)-1) {
            my $this_boot_time = $sorted_boot_times[$ind];
            
            if($group_start_ind < 0) {
                $group_start_ind = $ind;
                $group_end_ind   = $ind;

                my ($this_tx_time, $this_rx_time) = split(":", $this_boot_times{BOOT_TIME}{$this_boot_time}{TX_RX});
                $this_tx_time += 0; $this_rx_time += 0;

                $this_group_info{TX_TIME}{$this_tx_time}{RX_TIME}{$this_rx_time} = 1;

                next;
            }

            my $last_boot_time = $sorted_boot_times[$group_end_ind];
            my $first_boot_time = $sorted_boot_times[$group_start_ind];

            my $span = $this_boot_time - $last_boot_time;
            if($span > $BOOT_TIME_SPAN) {
                ## new group
                my $group_span = $last_boot_time - $first_boot_time;
                my $group_size = scalar(keys %{ $this_group_info{TX_TIME} });
                print "  span=$group_span, size=$group_size\n" if($DEBUG4);
                
                if($group_span < $BOOT_TIME_SPAN and $group_size > $MIN_POINTS) {
                    ## very likely we find a correct frequency for this group
                    my ($freq, $likelihood) = estimate_frequency(\%this_group_info);
                    print "    best freq=$freq, likelihood=$likelihood\n" if($DEBUG4);

                    if($likelihood < $BOOT_TIME_SPAN) {
                        print "      ==> new device $num_devices\n" if($DEBUG4);

                        %{ $group_info{GROUP}{$num_devices} } = %this_group_info;
                        $group_info{GROUP}{$num_devices}{FREQ} = $freq;
                        $group_info{GROUP}{$num_devices}{LIKELIHOOD} = $likelihood;

                        $num_devices ++;
                    }
                }

                
                $group_start_ind = $ind;
                $group_end_ind   = $ind;

                my ($this_tx_time, $this_rx_time) = split(":", $this_boot_times{BOOT_TIME}{$this_boot_time}{TX_RX});
                $this_tx_time += 0; $this_rx_time += 0;

                %this_group_info = ();
                $this_group_info{TX_TIME}{$this_tx_time}{RX_TIME}{$this_rx_time} = 1;
            }
            else {
                ## same group
                $group_end_ind   = $ind;

                my ($this_tx_time, $this_rx_time) = split(":", $this_boot_times{BOOT_TIME}{$this_boot_time}{TX_RX});
                $this_tx_time += 0; $this_rx_time += 0;

                $this_group_info{TX_TIME}{$this_tx_time}{RX_TIME}{$this_rx_time} = 1;
            }

        }
    }  ## end all frequencies


    print "number of devices: $num_devices\n";
    foreach my $dev_ind (0 .. $num_devices-1) {
        print "device $dev_ind: freq = ".$group_info{GROUP}{$dev_ind}{FREQ}.", likelihood = ".$group_info{GROUP}{$dev_ind}{LIKELIHOOD}."\n";
    }

}
## end of estimate_boot_times
##################################################





##################################################
## estimate_frequency
##    Given a set of pakcets with TCP timestamp and receiving time from a single machine,
##    this function estimate the frequency of the machine.
##    The idea is that as long as we find the correct frequency, the estimated boot time should be very similar.
##
## - input: %ip_info;
##   {TX_TIME}{sending time}{RX_TIME}{receiving time}
##
## - output:
##   a) freq: the estimated frequency
##   b) likelihood: the time interval of min and max calculated boot time
##
## - parameters
##
##################################################

sub estimate_frequency {
    my $ip_info_ref = shift @_;

    # print Dumper($ip_info_ref);

    ## we don't know the frequencies of all machines, so here listing all possible frequencies that we need to try
    my @possible_freq = (1 ... 1000);


    my $best_freq;
    my $likelihood = -1; ## how likely that the select frequency is that of the machine. The smaller is the better.

    foreach my $this_freq (@possible_freq) {
        print "." if($DEBUG3);

        my $min_boot_time = -1;
        my $max_boot_time = -1;
        my $first_pkt = 1;

        foreach my $this_tx_time (keys %{ $ip_info_ref->{TX_TIME} }) {
            print "T = $this_tx_time\n" if($DEBUG1);

            foreach my $this_rx_time (keys %{ $ip_info_ref->{TX_TIME}{$this_tx_time}{RX_TIME} }) {
                print "t = $this_rx_time\n" if($DEBUG1);

                my $this_boot_time = $this_rx_time - $this_tx_time / $this_freq;

                if($DEBUG1) {
                    print "t = $this_rx_time, T = $this_tx_time\n";
                    print "boot time ($this_freq) = $this_boot_time\n";
                }
                

                if($first_pkt == 1) {
                    $min_boot_time = $this_boot_time;
                    $max_boot_time = $this_boot_time;
                    $first_pkt = 0;
                }
                $min_boot_time = $this_boot_time if($this_boot_time < $min_boot_time);
                $max_boot_time = $this_boot_time if($this_boot_time > $max_boot_time);
            }
        }


        die "no min or max boot time\n" if($DEBUG0 and $first_pkt == 1);

        my $interval = $max_boot_time - $min_boot_time;
        if($likelihood < 0 or $likelihood > $interval) {
            $likelihood = $interval;
            $best_freq = $this_freq;
        }
    }
    print "\n" if($DEBUG3);
    

    return ($best_freq, $likelihood);
}
## end of estimate_frequency
##################################################

1;
