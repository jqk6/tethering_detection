// ---------------------------------------------------------
//
// pcap_throughput
//
//  reads in a pcap file and outputs basic throughput statistics
//
//  e.g. 
//      ./pcapParser /export/home/ychen/testbed/exp2/pcap/2013.06.24.AP.pcap
//      
// ---------------------------------------------------------

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
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
#define DEBUG4  (0)     /* entire http header and payload */

// defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_HDRLEN (14)



/*
 * Structure of an internet header, naked of options.
 *
 * Stolen from tcpdump source (thanks tcpdump people)
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip
{
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
    struct  in_addr ip_src, ip_dst; /* source and dest address */
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
    while (packet = pcap_next(handle, &header))
    {

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


        // --------------------------------
        // parse the IP header:
        // struct ip {
        // #if BYTE_ORDER == LITTLE_ENDIAN
        //         u_char  ip_hl:4,                /* header length (number of words) */
        //                 ip_v:4;                 /* version */
        // #endif
        // #if BYTE_ORDER == BIG_ENDIAN
        //         u_char  ip_v:4,                 /* version */
        //                 ip_hl:4;                /* header length */
        // #endif
        //         u_char  ip_tos;                 /* type of service */
        //         u_short ip_len;                 /* total length */
        //         u_short ip_id;                  /* identification */
        //         u_short ip_off;                 /* fragment offset field */
        // #define IP_RF 0x8000                    /* reserved fragment flag */
        // #define IP_DF 0x4000                    /* dont fragment flag */
        // #define IP_MF 0x2000                    /* more fragments flag */
        // #define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        //         u_char  ip_ttl;                 /* time to live */
        //         u_char  ip_p;                   /* protocol */
        //         u_short ip_sum;                 /* checksum */
        //         struct  in_addr ip_src,ip_dst;  /* source and dest address */
        // } __packed __aligned(4);
        pkt_ptr += ether_offset;  // skip past the Ethernet II header
        struct ip *ip_hdr = (struct ip *)pkt_ptr; // point to an IP header structure

        int packet_length = ntohs(ip_hdr->ip_len);
        int size_ip = ip_hdr->ip_hl * 4;
        unsigned short offset = ntohs(ip_hdr->ip_off) & IP_OFFMASK;


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


        // ----------
        // DEBUG
        // ----------
        if(DEBUG0) {
            printf("=> %ld %ld %s > ", header.ts.tv_sec, header.ts.tv_usec, inet_ntoa(ip_hdr->ip_src));
            printf("%s, ip_p=%d, ttl=%d, ip_hl=%d, ip_id=%d\n", inet_ntoa(ip_hdr->ip_dst), ip_hdr->ip_p, ip_hdr->ip_ttl, ip_hdr->ip_hl, ip_hdr->ip_id);
        }


        // --------------------------
        // format:
        //  <time> <src ip> <dest ip> <proto> <ttl> <id> <length>
        // printf("%ld %s > %s %d %d %d %d\n", 
        //     header.ts.tv_sec, 
        //     inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst), 
        //     ip_hdr->ip_p, 
        //     ip_hdr->ip_ttl,
        //     ntohs(ip_hdr->ip_id),
        //     ntohs(ip_hdr->ip_len)
        //     );
        printf("%ld %ld %s > ", header.ts.tv_sec, header.ts.tv_usec, inet_ntoa(ip_hdr->ip_src));
        printf("%s %d %d %d %d\n", 
            inet_ntoa(ip_hdr->ip_dst), 
            ip_hdr->ip_p, 
            ip_hdr->ip_ttl,
            ntohs(ip_hdr->ip_id),
            ntohs(ip_hdr->ip_len)
            );

    } //end internal loop for reading packets (all in one file)

out:
    pcap_close(handle);  //close the pcap file

    //output some statistics about the whole trace
    //byte_counter /= 1e6;  //convert to MB to make easier to read

    printf("Processed %d packets and %lu MBytes, in %d files\n", pkt_counter, byte_counter, argc - 1);
    return 0; //done
} //end of main() function
