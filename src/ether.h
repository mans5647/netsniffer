#pragma once

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_UNKNOWN "00:00:00:00:00:00"
#define H_PROTO_IP4 0x0800
#define H_PROTO_IP6 0x86DD
#define H_PROTO_ARP 0x0806
#define MAC_MAX_LEN 48
#define MAC_PRETTY_NAME MAC_MAX_LEN + 5
#define N_OCTETS 6


#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <WinSock2.h>

struct ether_header
{
    uint8_t mac_dst[N_OCTETS];
    uint8_t mac_src[N_OCTETS];
    uint16_t h_proto;

    ether_header() noexcept = default;
    ether_header(const ether_header & other)
    {
        std::copy(other.mac_dst, other.mac_dst + N_OCTETS, mac_dst);
        std::copy(other.mac_src, other.mac_src + N_OCTETS, mac_src);
        h_proto = other.h_proto;
    }

};

#define ETH_HEADER_SIZE sizeof(ether_header)

