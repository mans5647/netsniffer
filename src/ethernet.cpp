#include "ethernet.h"


Ethernet::Ethernet()
{
    std::fill(MacDestination.begin(), MacDestination.end(), '\0');
    std::fill(MacSource.begin(), MacSource.end(), '\0');
    EtherType = -1;
}

Ethernet &Ethernet::operator =(const Ethernet &other)
{
    MacDestination = other.MacDestination;
    MacSource = other.MacSource;
    EtherType = other.EtherType;
    ethernet_length = other.ethernet_length;
    return *this;
}

Ethernet::Ethernet(Ethernet &&other)
{
    MacDestination.swap(other.MacDestination);
    MacSource.swap(other.MacSource);

    EtherType = other.EtherType;
}

Ethernet::Ethernet(ether_header *rawFrame)
{
    const uint8_t * ptr_dst = rawFrame->mac_dst;
    const uint8_t * ptr_src = rawFrame->mac_src;

    for (auto i = 0; i < N_OCTETS; i++)
    {
        MacDestination.at(i) = (*ptr_dst);
        MacSource.at(i) = (*ptr_src);
        ptr_dst++;
        ptr_src++;
    }

    EtherType = ntohs(rawFrame->h_proto);



    ethernet_length = EtherType;
}

bool Ethernet::hasNextProtocol(const Ethernet &value)
{
    const uint16_t proto = value.getEtherType();
    return (proto == H_PROTO_ARP || proto == H_PROTO_IP4 || proto == H_PROTO_IP6) ? true : false;

}
