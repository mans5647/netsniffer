#pragma once

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_UNKNOWN "00:00:00:00:00:00"
#define H_PROTO_IP4 0x0800
#define H_PROTO_IP6 0x86DD
#define H_PROTO_ARP 0x0806
#define MAC_MAX_LEN 48
#define MAC_PRETTY_NAME_SIZE MAC_MAX_LEN + 5
#define MAC_OCTETS 6

#include <cstdint>

struct ether_header
{
    uint8_t mac_dest[MAC_OCTETS];
    uint8_t mac_src[MAC_OCTETS];
    uint16_t h_proto;
};

#define ETH_HEADER_SIZE sizeof(ether_header)

