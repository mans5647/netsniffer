#include "helpers.h"
#include "ether.h"
#include "proto.h"
#include <cctype>

#if defined(_WIN32)
    #include <ip2string.h>
    #pragma comment(lib, "ntdll.lib")
#elif __linux__
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

bool isPrintable(const uint8_t sym)
{
    return std::isprint(sym) != 0 ? true : false;
}
