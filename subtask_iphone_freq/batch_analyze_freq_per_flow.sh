#!/bin/bash

for file in "2013.07.11.HTC.iperf.2min.pcap.txt" "2013.07.11.Samsung.iperf.2min.pcap.txt" "2013.07.12.Samsung.iperf_again.pcap.txt" "2013.07.12.Samsung_iphone.fc2video_iperf.pcap.txt" "2013.10.14.iphone.tr1.iperf.pcap.txt" "2013.10.14.iphone.tr2.iperf.pcap.txt" "2013.10.14.iphone.tr3.iperf.pcap.txt" "2013.10.14.windows.iperf.pcap.txt"; do
    
    for ewma_alpha in 0.2 0.5 0.8; do
        for seg_len in 5000 10000 50000 1000000000; do
            perl analyze_freq_per_flow.pl ../data/testbed/tcp_traces/text5/${file} ${seg_len} ${ewma_alpha}
        done

        for ini_sec in 5 10 15 20 25 30 40 50; do
            perl analyze_freq_per_flow2.pl ../data/testbed/tcp_traces/text5/${file} ${ini_sec} ${ewma_alpha}
        done


        #####
        perl analyze_freq_per_flow3.pl ../data/testbed/tcp_traces/text5/${file} ${ewma_alpha} 0 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55

        perl analyze_freq_per_flow3.pl ../data/testbed/tcp_traces/text5/${file} ${ewma_alpha} 1 20 25 30 35 40 50 55 60 100

        perl analyze_freq_per_flow3.pl ../data/testbed/tcp_traces/text5/${file} ${ewma_alpha} 2 30 50 100 150 200 250 300 350 400 450 500 600

        perl analyze_freq_per_flow3.pl ../data/testbed/tcp_traces/text5/${file} ${ewma_alpha} 3 30 40 50 60 70 80 90 100 110 120 130 150

        perl analyze_freq_per_flow3.pl ../data/testbed/tcp_traces/text5/${file} ${ewma_alpha} 4 10 11 12 13 14 15 20 30
    done

    #####
    perl analyze_freq_per_flow4.pl ../data/testbed/tcp_traces/text5/${file} 0 2 10 100 128 200 250 1000
    perl analyze_freq_per_flow4.pl ../data/testbed/tcp_traces/text5/${file} 1 1 10 100 500 1000
    perl analyze_freq_per_flow4.pl ../data/testbed/tcp_traces/text5/${file} 3 1 2 10 64 100 128 200 256 500 600 700 800 900 1000
done
