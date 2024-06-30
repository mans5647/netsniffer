#ifndef DNS_UTILS_H
#define DNS_UTILS_H
#include <cstdint>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include "dns.h"

size_t ParseQuestion(const uint16_t, const uint8_t*, DnsQuestion*);
size_t ParseAnswer(const uint8_t*,   const uint8_t *,  DnsAnswer*);

#endif // DNS_UTILS_H
