#include "ethernet.h"
#include <cstdio>
#include <QDebug>
#if _WIN32
    #include <WinSock2.h>
    #include <WS2tcpip.h>
#elif __linux__
    #include <arpa/inet.h>
#endif

Ethernet::Ethernet(const ether_header * hdr)
{
    ether_type = ntohs(hdr->h_proto);

    // now, we need to transform both MAC-addresses to pretty hexadecimal strings
    source.resize(MAC_PRETTY_NAME_SIZE + 1);
    destination.resize(MAC_PRETTY_NAME_SIZE + 1);

    std::snprintf(source.data(), MAC_PRETTY_NAME_SIZE, MAC_FMT,
        hdr->mac_src[0],
        hdr->mac_src[1],
        hdr->mac_src[2],
        hdr->mac_src[3],
        hdr->mac_src[4],
        hdr->mac_src[5]);

    std::snprintf(destination.data(), MAC_PRETTY_NAME_SIZE, MAC_FMT,
        hdr->mac_dest[0],
        hdr->mac_dest[1],
        hdr->mac_dest[2],
        hdr->mac_dest[3],
        hdr->mac_dest[4],
        hdr->mac_dest[5]);
}

Ethernet::Ethernet(Ethernet &&other)
{
    this->destination = std::move(other.destination);
    this->source = std::move(other.source);
    this->ether_type = other.ether_type;


}

Ethernet& Ethernet::operator=(Ethernet && other)
{
    this->destination = std::move(other.destination);
    this->source = std::move(other.source);
    this->ether_type = other.ether_type;
    return *this;
}
Ethernet::Ethernet()
{
    this->destination = "";
    this->source = "";
    this->ether_type = -1;
}

std::string_view Ethernet::MacSource() const
{
    return source;
}

std::string_view Ethernet::MacDestination() const
{
    return destination;
}

bool Ethernet::hasNextProtocol()
{

    switch (EtherType())
    {
        case H_PROTO_ARP:
        case H_PROTO_IP4:
        case H_PROTO_IP6:
            return true;
    }

    return false;
}

bool Ethernet::hasNextProtocol() const
{
    switch (EtherType())
    {
        case H_PROTO_ARP:
        case H_PROTO_IP4:
        case H_PROTO_IP6:
            return true;
    }

    return false;
}
