#include <cstdint>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <in6addr.h>
#include "dns.h"

struct tcphdr
{
    uint16_t    sport;                /* source port (ntohs) */
    uint16_t    dport;                /* destination port (ntohs) */
    uint32_t    seq_num; // ntohl
    uint32_t    ack_num; // ntohl
    uint8_t     off_rsv; // length: (off_rsv >> 4) & 15; reserved = (off_rsv & 15)
    uint8_t     flags;
    uint16_t    window_size; // ntohs
    uint16_t    chk_sum; // ntohs
    uint16_t    urgent_pointer; // ntohs
};

#define TH_FIN            0x01
#define TH_SYN            0x02
#define TH_RST            0x04
#define TH_PUSH           0x08
#define TH_ACK            0x10
#define TH_URG            0x20
#define TH_ECE            0x40
#define TH_CWR            0x80

struct udphdr
{
    uint16_t uh_sport;                /* source port */
    uint16_t uh_dport;                /* destination port */
    uint16_t uh_ulen;                /* udp length */
    uint16_t uh_sum;                /* udp checksum */
};

#define IP_MAX_LEN 16
struct ip {
    uint8_t	ip_vhl;
    uint8_t  ip_tos;		/* type of service */
    uint16_t ip_len;		/* total length */
    uint16_t ip_id;		/* identification */
    uint16_t ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t  ip_ttl;		/* time to live */
    uint8_t  ip_p;			/* protocol */
    uint16_t ip_sum;		/* checksum */
    struct	  in_addr ip_src, ip_dst; /* source and dest address */
};


#define V6_BUF_SIZE_MAX 50
#define V6_BUF_SIZE_MIN 46

struct ip6
{
    uint32_t vtf; // version + traffic + flow label : 4
    uint16_t payload_len; // 2
    uint8_t nxt_hdr; // 1
    uint8_t hop; // 1
    in6_addr src_addr; // 16
    in6_addr dst_addr; // 16
};


struct Arp
{
    uint16_t h_type;
    uint16_t p_type;
    uint8_t h_len;
    uint8_t p_len;
    uint16_t operation;
    uint8_t sender_mac[6];
    uint8_t sender_laddr[4];
    uint8_t target_mac[6];
    uint8_t target_laddr[4];
};


struct ICMP
{
    uint8_t type;
    uint8_t code;
    uint16_t chk_sum;
};



#define IPV(value) (value >> 4) & 15
#define IP_HL(value) (value & 15)
#define IP_OFFMASK 0x1fff


#define TCP_NEXT 6
#define UDP_NEXT 17
#define IGMP_NEXT 2
#define ICMP_NEXT 1
