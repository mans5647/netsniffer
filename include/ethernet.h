#ifndef ETHERNET_H
#define ETHERNET_H


#include "ether.h"
#include <cstdint>
#include <string>
#include <string_view>


// comfortable wrapper class for ethernet frame
class Ethernet
{
public:
    Ethernet();
    Ethernet(const ether_header*); // build object from raw header
    Ethernet(Ethernet && other);
    Ethernet& operator=(Ethernet && other);
    std::uint16_t EtherType() const { return ether_type; } // returns Next underlying protocol
    std::uint16_t EthernetLength() const { return ether_type; } // same as getEtherType()

    std::string_view MacSource() const;
    std::string_view MacDestination() const;

    bool hasNextProtocol();
    bool hasNextProtocol() const;
    bool isNextArp() const { return EtherType() == H_PROTO_ARP; }
private:
    std::uint16_t ether_type;
    std::string source, destination; // sender and receiver's MACs
};

#endif // ETHERNET_H
