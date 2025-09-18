#ifndef DNS_UTILS_H
#define DNS_UTILS_H
#include <cstdint>

#if defined(_WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#include "dns.h"

std::ptrdiff_t ParseQuestion(const uint8_t*, DnsQuestion*);
std::ptrdiff_t ParseAnswer(const uint8_t*,DnsAnswer*);

#endif // DNS_UTILS_H
