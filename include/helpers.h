#ifndef HELPERS_H
#define HELPERS_H

#include <QObject>
#include <cstdint>
#include <ctype.h>
#include <string>

#if defined(_WIN32)
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <in6addr.h>
#else
    #include <netinet/in.h>
#endif





#define setconn(sender, signal, context, slot) QObject::connect(sender, signal, context, slot);
#define C_UNSAFE_CAST(to, expr) (to)(expr)
#define CPPUNSAFE_CAST(to, expr) reinterpret_cast<to>(expr)
#define SAFE_CAST(to, expr) static_cast<to>(expr)

#define ADDR_V4_BUFLEN_MIN 15

#define U_SHORT_TYPE 2
#define U_LONG_TYPE 4

#define FILE_ADDR "./"
#define FILE_FORMAT_CHUNK "dump"

bool isPrintable(const uint8_t);
const char* FromIPv4Address(char *, size_t, const in_addr*);
const char *FromIPv6Address(char *, size_t, const in6_addr *);


void prettify_mac(char*, const uint8_t*, size_t);


#endif
