#ifndef DNS_H
#define DNS_H


#define DNS_FLAGS_QR_MASK  0x8000
#define DNS_FLAGS_OPCODE_MASK    0x7800
#define DNS_FLAGS_AA_SERVER 0x400
#define DNS_FLAGS_TC 0x200
#define DNS_FLAGS_RD 0x0100
#define DNS_FLAGS_RA 0x0080



#define DNS_FLAGS_QR_QUERY 0x0000
#define DNS_FLAGS_QR_REPLY 0x8000


#define DNS_FLAGS_QUERY_STANDARD 0x0000
#define DNS_FLAGS_QUERY_INVERSE  0x0800
#define DNS_FLAGS_QUERY_STATUS   0x1000


#define DNS_FLAGS_RCODE_MASK            0x000f
#define DNS_FLAGS_RCODE_NO_ERROR        0x0000
#define DNS_FLAGS_RCODE_FORMAT_ERROR    0x0001
#define DNS_FLAGS_RCODE_SERVER_FAILURE  0x0002
#define DNS_FLAGS_RCODE_NAME_ERROR      0x0003
#define DNS_FLAGS_RCODE_NOT_IMPLEMENTED 0x0004
#define DNS_FLAGS_RCODE_REFUSED         0x0005


#define DNS_TYPE_A		1
#define DNS_TYPE_NS	2
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_MB	7
#define DNS_TYPE_MG	8
#define DNS_TYPE_MR	9
#define DNS_TYPE_NULL	10
#define DNS_TYPE_WKS	11
#define DNS_TYPE_PTR	12
#define DNS_TYPE_HINFO	13
#define DNS_TYPE_MINFO	14
#define DNS_TYPE_MX	15
#define DNS_TYPE_TXT	16
#define DNS_TYPE_RP	17
#define DNS_TYPE_AFSDB	18
#define DNS_TYPE_X25	19
#define DNS_TYPE_ISDN	20
#define DNS_TYPE_RT	21
#define DNS_TYPE_AAAA	28
#define DNS_TYPE_LOC	29
#define DNS_TYPE_SRV	33
#define DNS_TYPE_HTTPS 65
#define DNS_TYPE_AXFR	252
#define DNS_TYPE_MAILB	253
#define DNS_TYPE_MAILA	254
#define DNS_TYPE_ANY	255

#define DNS_CLASS_IN 1
#define DNS_CLASS_CS 2
#define DNS_CLASS_CH 3
#define DNS_CLASS_HS 4

#define DNS_HEADER_SIZE 12
#define DNS_DATA_LEN 128

#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SFAIL     2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NIMPL     4
#define DNS_RCODE_REFUSED   5



#define DNS_NAME_OFFCALC(value) (value & 255)

#include <QByteArray>
#include <WinSock2.h>


struct dns_address_t
{
    in_addr address;
};

struct dns_cname_t
{
    uint8_t data[DNS_DATA_LEN];
};

struct DnsQuestion
{
    QByteArray name;
    uint16_t type;           // type (A, A6, MX)
    uint16_t cl_name;            // class name
};

#define DNS_ANSWER_MEMBER_CONST_SIZE 12

struct DnsAnswer
{
    uint16_t    offset;    // name offset
    uint16_t    type;           // type (Address or Canonical name)
    uint16_t    cl_name;        // class name
    uint32_t    ttl;            // ttl
    uint16_t    length;         // length of data

    uint8_t name[DNS_DATA_LEN];

    union data
    {
        dns_address_t host_addr;
        dns_cname_t cname;
    };
    data adata;
};


struct dnshdr
{
    uint16_t id;            // ID field - 2 bytes
    uint16_t flags;         // FLAGS - 2 bytes
    uint16_t n_questions;   // number of questions
    uint16_t n_answers;     // number of answers
    uint16_t n_authority;   // A number of authority RRs
    uint16_t n_addinfo;     // A number of additional RRs
};




#endif // DNS_H
