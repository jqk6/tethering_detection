#!/bin/perl

##################################################
## Author: Yi-Chao Chen 
## 2013/06/17 @ Narus 
##
## Group packets in flows, and analyze TTL, tput, pkt number, packet length entropy.
##
## - input: parsed_pcap_text
##     format
##     <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
##
## - output
##     ./output/
##     a) file.<id>.rtts.txt: 
##          the RTT to different destinations
##          format:
##              <src ip>, <dst ip>, <RTTs>
##
##  e.g.
##      perl analyze_sprint_tcp_rtt.pl /data/ychen/sprint/text2/omni.out.49.eth.pcap.txt
##################################################

use strict;


#####
## DEBUG
my $DEBUG0 = 1; ## check error
my $DEBUG1 = 0; ## print for debug
my $DEBUG2 = 0; ## print for debug


#####
## variables
my $output_dir = "./output";

my $file_name;
my $file_id;

my %ip_info;        ## ip pair seq and ack info
                    ## {IP}{src ip}{PORT}{src port}{dst ip}{dst port}{time}{SEQ}
                    ## {IP}{src ip}{PORT}{src port}{dst ip}{dst port}{time}{ACK}
                    ## {IP}{src ip}{PORT}{src port}{dst ip}{dst port}{time}{IS_ACK}
                    ## {IP}{src ip}{PORT}{src port}{dst ip}{dst port}{time}{PAYLOAD_LEN}
                    ## {CONN}{SRC}{src ip}{DST}{dst ip}{RTT}{rtts}


#####
## check input
if(@ARGV != 1) {
    print "wrong number of input\n";
    exit;
}
$file_name = $ARGV[0];
print "input file = $file_name\n" if($DEBUG1);
my @dir_structure = split(/\//, $file_name);
$file_id = $1+0 if(pop(@dir_structure) =~ /(\d+)/);
print "file id: $file_id\n" if($DEBUG1);


#####
## main starts here
print STDERR "start to read data..\n" if($DEBUG2);
open FH, "$file_name" or die $!;
while(<FH>) {
    next if($_ =~ /Processed/); ## used to ignore the last line in the input file
    
    ## format
    ##   <time> <time usec> <src ip> <dest ip> <proto> <ttl> <id> <length> <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len>
    my ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len) = split(/\s+>*\s*/, $_);

    $time += 0; $time_usec += 0; $proto += 0; $ttl += 0; $id += 0; $len += 0; $s_port += 0; $d_port += 0; $seq += 0; $ack += 0; $is_fin += 0; $is_syn += 0; $is_rst += 0; $is_push += 0; $is_ack += 0; $is_urp += 0; $is_ece += 0; $is_cwr += 0; $win += 0; $urp += 0; $payload_len += 0;
    print join(",", ($time, $time_usec, $src, $dst, $proto, $ttl, $id, $len, $s_port, $d_port, $seq, $ack, $is_fin, $is_syn, $is_rst, $is_push, $is_ack, $is_urp, $is_ece, $is_cwr, $win, $urp, $payload_len))."\n" if($DEBUG1);


    $ip_info{IP}{$src}{PORT}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{SEQ} = $seq;
    $ip_info{IP}{$src}{PORT}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{ACK} = $ack;
    $ip_info{IP}{$src}{PORT}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{IS_ACK} = $is_ack;
    $ip_info{IP}{$src}{PORT}{$s_port}{$dst}{$d_port}{$time + $time_usec/1000000}{PAYLOAD_LEN} = $payload_len;

}
close FH;


#####
## Analyze
print STDERR "start to analyze result..\n" if($DEBUG2);
my %checked_ips;        ## stored ips which are already checked, so we don't need to check them again

foreach my $this_src_ip (keys %{ $ip_info{IP} }) {
    foreach my $this_src_port (keys %{ $ip_info{IP}{$this_src_ip}{PORT} }) {
        foreach my $this_dst_ip (keys %{ $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port} }) {
            foreach my $this_dst_port (keys %{ $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip} }) {

                ## check if this IP pair is already checked
                if(exists($checked_ips{"$this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port"}) or
                   exists($checked_ips{"$this_dst_ip:$this_dst_port>$this_src_ip:$this_src_port"})
                ) {
                    print "$this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port is already ehcecked\n" if($DEBUG1);
                    next;
                }
                else {
                    $checked_ips{"$this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port"} = 1;
                }


                ## if not checked
                print "- $this_src_ip:$this_src_port>$this_dst_ip:$this_dst_port\n" if($DEBUG2);
                my %tcp_info;


                my @src_times = sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port} });
                my @dst_times = sort {$a <=> $b} (keys %{ $ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port} });

                my $src_ind = 0;
                my $dst_ind = 0;
                while($src_ind < scalar(@src_times) and $dst_ind < scalar(@dst_times) ) {
                    my $this_src_time = $src_times[$src_ind];
                    my $this_dst_time = $dst_times[$dst_ind];

                    if($this_src_time < $this_dst_time) {

                        my $this_s2d_seq = $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{SEQ};
                        my $this_s2d_len = $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{PAYLOAD_LEN};
                        my $this_s2d_seq_end;
                        if($this_s2d_len > 0) {
                            $this_s2d_seq_end = $this_s2d_seq + $this_s2d_len - 1;
                        }
                        else {
                            $this_s2d_seq_end = $this_s2d_seq;
                        }
                        my $this_s2d_ack = $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{ACK};

                        ## print src info
                        print "$this_src_time s>d: seq=".$this_s2d_seq."(".$this_s2d_len.")".$this_s2d_seq_end.", ack=".$this_s2d_ack."(".$ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{IS_ACK}.")\n" if($DEBUG2);



                        # if(exists $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} and $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} > 0) {
                        #     if($this_s2d_ack >= $tcp_info{"$this_dst_ip:$this_src_ip"}{SEQ}) {
                        #         my $rtt = $this_src_time - $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME};
                        #         push(@{ $ip_info{CONN}{SRC}{$this_dst_ip}{DST}{$this_src_ip}{RTT} }, $rtt);


                        #         print "  (s2d) ==> ".$this_src_time."-".$tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                        #         $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} = -1;
                        #     }
                        # }
                        if(abs($this_s2d_ack - $tcp_info{"$this_dst_ip:$this_src_ip"}{SEQ}) <= 1 and
                           $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} > 0
                        ) {
                            my $rtt = $this_src_time - $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME};
                            push(@{ $ip_info{CONN}{SRC}{$this_dst_ip}{DST}{$this_src_ip}{RTT} }, $rtt);


                            print "  (s2d) ==> ".$this_src_time."-".$tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                            $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} = -1;
                        }


                        $tcp_info{"$this_src_ip:$this_dst_ip"}{SEQ} = $this_s2d_seq_end;
                        $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} = $this_src_time;


                        $src_ind ++;
                    }
                    elsif($this_src_time > $this_dst_time) {
                        my $this_d2s_seq = $ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{SEQ};
                        my $this_d2s_len = $ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{PAYLOAD_LEN};
                        my $this_d2s_seq_end;
                        if($this_d2s_len > 0) {
                            $this_d2s_seq_end = $this_d2s_seq + $this_d2s_len - 1;
                        }
                        else {
                            $this_d2s_seq_end = $this_d2s_seq;
                        }
                        my $this_d2s_ack = $ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{ACK};

                        ## print dst info
                        print "$this_dst_time d>s: seq=".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{SEQ}."(".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{PAYLOAD}.")".($ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{SEQ}+$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{PAYLOAD}).", ack=".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{ACK}."(".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{IS_ACK}.")\n" if($DEBUG2);


                        # if(exists $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} and $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} > 0) {
                        #     if($this_d2s_ack >= $tcp_info{"$this_src_ip:$this_dst_ip"}{SEQ}) {
                        #         my $rtt = $this_dst_time - $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME};
                        #         push(@{ $ip_info{CONN}{SRC}{$this_src_ip}{DST}{$this_dst_ip}{RTT} }, $rtt);


                        #         print "  (d2s) ==> ".$this_dst_time."-".$tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                        #         $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} = -1;

                        #     }
                        # }
                        if(abs($this_d2s_ack - $tcp_info{"$this_src_ip:$this_dst_ip"}{SEQ}) <= 1 and
                           $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} > 0
                        ) {
                            my $rtt = $this_dst_time - $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME};
                            push(@{ $ip_info{CONN}{SRC}{$this_src_ip}{DST}{$this_dst_ip}{RTT} }, $rtt);


                            print "  (d2s) ==> ".$this_dst_time."-".$tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                            $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} = -1;
                        }

                        
                        $tcp_info{"$this_dst_ip:$this_src_ip"}{SEQ} = $this_d2s_seq_end;
                        $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} = $this_dst_time;


                        $dst_ind ++;
                    }
                    else {
                        ## send and ack at the same time??
                        my $this_s2d_seq = $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{SEQ};
                        my $this_s2d_len = $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{PAYLOAD_LEN};
                        my $this_s2d_seq_end;
                        if($this_s2d_len > 0) {
                            $this_s2d_seq_end = $this_s2d_seq + $this_s2d_len - 1;
                        }
                        else {
                            $this_s2d_seq_end = $this_s2d_seq;
                        }
                        my $this_s2d_ack = $ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{ACK};

                        ## print src info
                        print "$this_src_time s>d: seq=".$ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{SEQ}."(".$ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{PAYLOAD_LEN}.")".($ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{SEQ}+$ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{PAYLOAD}).", ack=".$ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{ACK}."(".$ip_info{IP}{$this_src_ip}{PORT}{$this_src_port}{$this_dst_ip}{$this_dst_port}{$this_src_time}{IS_ACK}.")\n" if($DEBUG2);



                        # if(exists $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} and $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} > 0) {
                        #     if($this_s2d_ack >= $tcp_info{"$this_dst_ip:$this_src_ip"}{SEQ}) {
                        #         my $rtt = $this_src_time - $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME};
                        #         push(@{ $ip_info{CONN}{SRC}{$this_dst_ip}{DST}{$this_src_ip}{RTT} }, $rtt);


                        #         print "  (s2d) ==> ".$this_src_time."-".$tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                        #         $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} = -1;
                        #     }
                        # }
                        if(abs($this_s2d_ack - $tcp_info{"$this_dst_ip:$this_src_ip"}{SEQ}) <= 1 and
                           $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} > 0
                        ) {
                            my $rtt = $this_src_time - $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME};
                            push(@{ $ip_info{CONN}{SRC}{$this_dst_ip}{DST}{$this_src_ip}{RTT} }, $rtt);


                            print "  (s2d) ==> ".$this_src_time."-".$tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                            $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} = -1;
                        }

                        $tcp_info{"$this_src_ip:$this_dst_ip"}{SEQ} = $this_s2d_seq_end;
                        $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} = $this_src_time;


                        my $this_d2s_seq = $ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{SEQ};
                        my $this_d2s_len = $ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{PAYLOAD_LEN};
                        my $this_d2s_seq_end;
                        if($this_d2s_len > 0) {
                            $this_d2s_seq_end = $this_d2s_seq + $this_d2s_len - 1;
                        }
                        else {
                            $this_d2s_seq_end = $this_d2s_seq;
                        }
                        my $this_d2s_ack = $ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{ACK};

                        ## print dst info
                        print "$this_dst_time d>s: seq=".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{SEQ}."(".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{PAYLOAD}.")".($ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{SEQ}+$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{PAYLOAD}).", ack=".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{ACK}."(".$ip_info{IP}{$this_dst_ip}{PORT}{$this_dst_port}{$this_src_ip}{$this_src_port}{$this_dst_time}{IS_ACK}.")\n" if($DEBUG2);


                        # if(exists $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} and $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} > 0) {
                        #     if($this_d2s_ack >= $tcp_info{"$this_src_ip:$this_dst_ip"}{SEQ}) {
                        #         my $rtt = $this_dst_time - $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME};
                        #         push(@{ $ip_info{CONN}{SRC}{$this_src_ip}{DST}{$this_dst_ip}{RTT} }, $rtt);


                        #         print "  (d2s) ==> ".$this_dst_time."-".$tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                        #         $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} = -1;
                        #     }
                        # }
                        if(abs($this_d2s_ack - $tcp_info{"$this_src_ip:$this_dst_ip"}{SEQ}) <= 1 and
                           $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} > 0
                        ) {
                            my $rtt = $this_dst_time - $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME};
                            push(@{ $ip_info{CONN}{SRC}{$this_src_ip}{DST}{$this_dst_ip}{RTT} }, $rtt);


                            print "  (d2s) ==> ".$this_dst_time."-".$tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME}."=$rtt\n" if($DEBUG2);


                            $tcp_info{"$this_src_ip:$this_dst_ip"}{LAST_TIME} = -1;
                        }

                        
                        $tcp_info{"$this_dst_ip:$this_src_ip"}{SEQ} = $this_d2s_seq_end;
                        $tcp_info{"$this_dst_ip:$this_src_ip"}{LAST_TIME} = $this_dst_time;


                        $src_ind ++;
                        $dst_ind ++;
                    }
                }
            }
        }
    }
}



#####
## output
my $file_output = "file.$file_id.rtts.txt";
open FH, "> $output_dir/$file_output";
foreach my $this_src (keys %{ $ip_info{CONN}{SRC} }) {
    foreach my $this_dst (keys %{ $ip_info{CONN}{SRC}{$this_src}{DST} }) {
        print FH "$this_src, $this_dst, ".join(", ", @{ $ip_info{CONN}{SRC}{$this_src}{DST}{$this_dst}{RTT} })."\n";
    }
}
close FH;



