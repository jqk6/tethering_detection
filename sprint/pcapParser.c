// ---------------------------------------------------------
//
// pcap_throughput
//
//  reads in a pcap file and outputs basic throughput statistics
//
//  e.g. 
//      ./pcapParser /data/ychen/sprint/pcap/omni.out.49.eth.pcap
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


#define DEBUG0  (0)

// defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_HDRLEN (14)



// Function Definition
u_int16_t handle_ethernet(const struct pcap_pkthdr *pkthdr, const u_char *packet);
u_char *handle_IP(const struct pcap_pkthdr *pkthdr, const u_char *packet);


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


/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
u_int16_t handle_ethernet(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout, "Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
    fprintf(stdout, "ETH: ");
    fprintf(stdout, "%s "
            , ether_ntoa((struct ether_addr *)eptr->ether_shost));
    fprintf(stdout, "%s "
            , ether_ntoa((struct ether_addr *)eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    {
        fprintf(stdout, "(IP)");
    }
    else  if (ether_type == ETHERTYPE_ARP)
    {
        fprintf(stdout, "(ARP)");
    }
    else  if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        fprintf(stdout, "(RARP)");
    }
    else
    {
        fprintf(stdout, "(?)");
    }
    fprintf(stdout, " %d\n", length);

    return ether_type;
}



u_char *handle_IP(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int i;

    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip *)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d", length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if (version != 4)
    {
        fprintf(stdout, "Unknown version %d\n", version);
        return NULL;
    }

    /* check header length */
    if (hlen < 5 )
    {
        fprintf(stdout, "bad-hlen %d \n", hlen);
    }

    /* see if we have as much packet as we should */
    if (length < len)
        printf("\ntruncated IP - %d bytes missing\n", len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0 ) /* aka no 1's in first 13 bits */
    {
        /* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout, "IP: ");
        fprintf(stdout, "%s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout, "%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                hlen, version, len, off);
    }

    return NULL;
}


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
        else {
            fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);
            unknown_ethernet_cnt ++;
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
        unsigned short offset = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

        if (ip_hdr->ip_p != 4)   //IP-ENCAP
        {
            not_ipv4_cnt ++;
            continue;
        }
        if (offset != 0)   // ignore IP fragments
        {
            // XXX: update byte counter??
            fragment_cnt ++;
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
        // remove the first layer of IP (specific to Narus trace??)
        ip_hdr = (struct ip *)(pkt_ptr + ip_hdr->ip_hl * 4);    // IHL is in words


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
        continue;

        //check to see if the next second has started, for statistics purposes
        if (current_ts == 0)    //this takes care of the very first packet seen
        {
            current_ts = header.ts.tv_sec;
        }
        else if (header.ts.tv_sec > current_ts)
        {
            printf("%ld KBps\n", cur_counter / 1000); //print
            cur_counter = 0; //reset counters
            current_ts = header.ts.tv_sec; //update time interval
        }

        cur_counter += packet_length;
        byte_counter += packet_length; //byte counter update
        pkt_counter++; //increment number of packets seen

    } //end internal loop for reading packets (all in one file)

out:
    pcap_close(handle);  //close the pcap file

    //output some statistics about the whole trace
    //byte_counter /= 1e6;  //convert to MB to make easier to read

    printf("Processed %d packets and %lu MBytes, in %d files\n", pkt_counter, byte_counter, argc - 1);
    return 0; //done
} //end of main() function
