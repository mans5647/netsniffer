#include "helpers.h"
#include "ether.h"
#include "proto.h"
#include <ip2string.h>

#pragma comment(lib, "ntdll.lib")

bool IsPrintable(const uint8_t * sym)
{
    return (std::isprint(*sym)) ? true : false;
}



const char* FromIPv4Address(char * buffer, size_t size, const in_addr * value)
{
    assert(size >= ADDR_V4_BUFLEN_MIN);
    return inet_ntop(AF_INET, value, buffer, size);

}

void prettify_mac(char * writeLoc, const uint8_t * readLoc, size_t size)
{
    assert(size >= MAC_PRETTY_NAME);
    snprintf(writeLoc, MAC_PRETTY_NAME, MAC_FMT, readLoc[0], readLoc[1], readLoc[2], readLoc[3],
             readLoc[4], readLoc[5]);
}

const char *FromIPv6Address(char * buffer, size_t size, const in6_addr * value)
{
    assert(size <= V6_BUF_SIZE_MAX);
    return RtlIpv6AddressToStringA(value, buffer);
}
