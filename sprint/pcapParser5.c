// ---------------------------------------------------------
//
// pcapParser5
//   copied form find_tcp_timestamp.c
//
//  reads in a pcap file and find if there is timestamp option
//
//  e.g.
//      ./find_tcp_timestamp /data/ychen/sprint/pcap/omni.out.49.eth.pcap
//
// ---------------------------------------------------------

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <string.h>


#define DEBUG0  (0)     /* pkt index */
#define DEBUG1  (0)     /* skip pkts */
#define DEBUG2  (0)     /* pkt headers */
#define DEBUG3  (0)     /* current test */
#define DEBUG4  (0)     /* TCP option */

// defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_HDRLEN (14)


struct my_ip {
    u_int8_t    ip_vhl;     /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;     /* type of service */
    u_int16_t   ip_len;     /* total length */
    u_int16_t   ip_id;      /* identification */
    u_int16_t   ip_off;     /* fragment offset field */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_int8_t    ip_ttl;     /* time to live */
    u_int8_t    ip_p;       /* protocol */
    u_int16_t   ip_sum;     /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/*************************************
** main function starts here
**************************************/
int main(int argc, char **argv)
{

    /*************************************
    ** variables
    **************************************/
    // statistics
    unsigned int pkt_counter = 0; // packet counter
    unsigned long byte_counter = 0; // total bytes seen in entire trace
    unsigned long cur_counter = 0; // counter for current 1-second interval
    unsigned long max_volume = 0;  // max value of bytes in one-second interval
    unsigned long current_ts = 0; // current timestamp
    unsigned int unknown_ethernet_cnt = 0;  // number of unknown ethernet packets
    unsigned int not_ipv4_cnt = 0;  // number of packets which are not IP v4
    unsigned int fragment_cnt = 0;  // number of fragmented packets

    // temporary packet buffers
    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; // The actual packet


    // check command line arguments
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [input pcap file]\n", argv[0]);
        exit(1);
    }


    /************************************
    ** iPhone trace need special treatment
    **************************************/
    int is_iphone = 0;
    if(strstr(argv[1], "iphone") != NULL) {
        is_iphone = 1;
    }


    /*************************************
    ** open the pcap file
    **************************************/
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
    handle = pcap_open_offline(argv[1], errbuf);   //call pcap library function

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1], errbuf);
        return (2);
    }


    /*************************************
    ** begin processing the packets in this particular file, one at a time
    **************************************/
    int cnt = 0;
    int cnt_tcp = 0;
    int cnt_tcp_ts = 0;
    while (packet = pcap_next(handle, &header))
    {
        cnt ++;

        if(DEBUG0) {
            printf("== %d ====================\n", cnt);
        }

        // header contains information about the packet (e.g. timestamp)
        u_char *pkt_ptr = (u_char *)packet; // cast a pointer to the packet data


        // --------------------------------
        // parse the first (ethernet) header, grabbing the type field
        // MAC dest (6 bytes), MAC src (6 bytes), 802.1Q (optional, 4 bytes), type (2 bytes), payload
        int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
        int ether_offset = 0;

        if (ether_type == ETHER_TYPE_IP) // most common
            ether_offset = 14;
        // XXX: double check this
        else if (ether_type == ETHER_TYPE_8021Q) // my traces have this
            ether_offset = 18;
        else if (ether_type == 0x0806) {
            if(DEBUG1) {
                printf("skip because it's an ARP\n");
            }

            continue;
        }
        else if (ether_type == 0x86DD) {
            if(DEBUG1) {
                printf("skip because it's IPv6\n");
            }

            continue;
        }
        else if (is_iphone == 1) {
            ether_offset = 0;
        }
        else {
            if(DEBUG1) {
                printf("Unknown ethernet type, %04X, skipping...\n", ether_type);
            }
            unknown_ethernet_cnt ++;

            continue;
        }

        pkt_ptr += ether_offset;  // skip past the Ethernet II header
        struct ip *ip_hdr = (struct ip *)pkt_ptr; // point to an IP header structure

        int packet_length = ntohs(ip_hdr->ip_len);
        unsigned short offset = ntohs(ip_hdr->ip_off) & IP_OFFMASK;


        if (ip_hdr->ip_p != 4)   //IP-ENCAP
        {
            // XXX: seems to have problem because of "some missing bytes in IP header of some packets"
            //      but not cause correctness issue yet..
            not_ipv4_cnt ++;


            // ----------
            // DEBUG
            // ----------
            if(DEBUG1) {
                printf("skip because it's IP-ENCAP: %d\n", ip_hdr->ip_p);
            }


            continue;
        }
        if (offset != 0)   // ignore IP fragments
        {
            // XXX: update byte counter??
            fragment_cnt ++;


            // ----------
            // DEBUG
            // ----------
            if(DEBUG1) {
                printf("skip because it's a fragment: %d\n", offset);
            }


            continue;
        }


        // --------------------------
        // remove the first layer of IP (specific to Narus trace??)
        ip_hdr = (struct ip *)(pkt_ptr + ip_hdr->ip_hl * 4);    // IHL is in words
        int size_ip = ip_hdr->ip_hl * 4;


        if(ip_hdr->ip_p == IPPROTO_TCP) {
            cnt_tcp ++;

            struct sniff_tcp *tcp_hdr = (struct sniff_tcp *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
            int size_tcp = TH_OFF(tcp_hdr)*4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }

            char is_fin = (tcp_hdr->th_flags & TH_FIN) ? 1 : 0;
            char is_syn = (tcp_hdr->th_flags & TH_SYN) ? 1 : 0;
            char is_rst = (tcp_hdr->th_flags & TH_RST) ? 1 : 0;
            char is_push = (tcp_hdr->th_flags & TH_PUSH) ? 1 : 0;
            char is_ack = (tcp_hdr->th_flags & TH_ACK) ? 1 : 0;
            char is_urg = (tcp_hdr->th_flags & TH_URG) ? 1 : 0;
            char is_ece = (tcp_hdr->th_flags & TH_ECE) ? 1 : 0;
            char is_cwr = (tcp_hdr->th_flags & TH_CWR) ? 1 : 0;
            int payload_size = ntohs(ip_hdr->ip_len) - size_ip - size_tcp;



            /*************************************
            ** find TCP options
            **************************************/
            int parsed_option_size = 0;
            while(size_tcp - parsed_option_size > 20) {

                u_char *tcp_option_ptr = ((u_char *)tcp_hdr) + 20 + parsed_option_size;
                u_char tcp_kind = tcp_option_ptr[0];

                if(tcp_kind == 1) {
                    // no-operation
                    parsed_option_size += 1;

                    if(DEBUG4) {
                        printf("TCP option 1\n");
                    }
                }
                else if(tcp_kind == 2) {
                    // Maximum Segment Size
                    parsed_option_size += 4;

                    if(DEBUG4) {
                        printf("TCP option 2\n");
                    }
                }
                else if(tcp_kind == 3) {
                    // WSOPT
                    parsed_option_size += 3;

                    if(DEBUG4) {
                        printf("TCP option 3\n");
                    }
                }
                else if(tcp_kind == 4) {
                    // SACK Permitted
                    parsed_option_size += 2;

                    if(DEBUG4) {
                        printf("TCP option 4\n");
                    }
                }
                else if(tcp_kind == 5) {
                    // SACK
                    // XXX: don't know how to deal with this one yet..
                    if(DEBUG4) {
                        printf("TCP option 5: SACK\ndon't know how to deal with this one yet..\n");
                    }
                    break;
                }
                else if(tcp_kind == 8) {
                    // TSOPT - Time Stamp Option
                    u_char tcp_op_len = tcp_option_ptr[1];
                    int tcp_tsval = ntohl(*(int *)&(tcp_option_ptr[2]));
                    int tcp_tsecr = ntohl(*(int *)&(tcp_option_ptr[6]));

                    if(DEBUG4) {
                        printf("TCP option 8\n");

                        if(tcp_op_len != 10) {
                            printf("tcp option kind 8 with wrong parsing format: len=%u\n", tcp_op_len);
                            break;
                        }

                        printf("pkt %d: ", cnt);
                    }


                    cnt_tcp_ts ++;

                    // --------------------------
                    // ip format:
                    //  <time> <src ip> <dest ip> <proto> <ttl> <id> <length>
                    printf("%ld %ld %s > ", header.ts.tv_sec, header.ts.tv_usec, inet_ntoa(ip_hdr->ip_src));
                    printf("%s %d %d %d %d ",
                        inet_ntoa(ip_hdr->ip_dst),
                        ip_hdr->ip_p,
                        ip_hdr->ip_ttl,
                        ntohs(ip_hdr->ip_id),
                        ntohs(ip_hdr->ip_len)
                        );

                    // --------------------------
                    // tcp format:
                    //  <src port> <dst port> <seq> <ack seq> <flag fin> <flag syn> <flag rst> <flag push> <flag ack> <flag urg> <flag ece> <flag cwr> <win> <urp> <payload len> <timestamp> <timestamp reply>
                    printf("%u %u %u %u %d %d %d %d %d %d %d %d %u %u %d %u %u\n",
                        ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport),
                        ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack),
                        is_fin, is_syn, is_rst, is_push, is_ack, is_urg, is_ece, is_cwr,
                        ntohs(tcp_hdr->th_win), ntohs(tcp_hdr->th_urp), payload_size,
                        tcp_tsval, tcp_tsecr);


                    // ----------
                    // DEBUG
                    // ----------
                    if(DEBUG2) {
                        printf("=> %ld %ld %s > ", header.ts.tv_sec, header.ts.tv_usec, inet_ntoa(ip_hdr->ip_src));
                        printf("%s, ip_p=%d, ttl=%d, ip_hl=%d, ip_id=%d\n", inet_ntoa(ip_hdr->ip_dst), ip_hdr->ip_p, ip_hdr->ip_ttl, ip_hdr->ip_hl, ntohs(ip_hdr->ip_id));
                        printf("=> src_port=%u, dst_port=%u, seq=%u, ack=%u, fin=%d, syn=%d, rst=%d, push=%d, ack=%d, urg=%d, ece=%d, cwr=%d, win=%u, urp=%u, payload=%d\n",
                            ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport),
                            ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack),
                            is_fin, is_syn, is_rst, is_push, is_ack, is_urg, is_ece, is_cwr,
                            ntohs(tcp_hdr->th_win), ntohs(tcp_hdr->th_urp), payload_size);
                        printf("=> tcp_hdr_size=%u, tcp_option_kind=%u, option_len=%u, tsval=%u, tsecr=%u\n",
                            size_tcp, tcp_kind, tcp_op_len,
                            tcp_tsval, tcp_tsecr);


                    }


                    // found what we need, don't need to continue
                    break;
                }
                else {
                    // XXX: shouldn't be here
                    if(DEBUG3) {
                        printf("unknown tcp option kind\n");
                    }
                    break;
                }


            }

        }   // END of TCP


    } //end internal loop for reading packets (all in one file)

out:
    pcap_close(handle);  //close the pcap file

    printf("Processed total # packets: %d/%d/%d\n", cnt_tcp_ts, cnt_tcp, cnt);

    //output some statistics about the whole trace
    //byte_counter /= 1e6;  //convert to MB to make easier to read

    // printf("Processed %d packets and %lu MBytes, in %d files\n", pkt_counter, byte_counter, argc - 1);
    return 0; //done
} //end of main() function
