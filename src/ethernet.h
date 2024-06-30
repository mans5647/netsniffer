#ifndef ETHERNET_H
#define ETHERNET_H


#include "ether.h"
#include <array>
#include <algorithm>
#include <QObject>


// comfortable wrapper class for ethernet frame

class Ethernet
{
public:

    enum class EthernetFrame
    {
        Version2,
        Version802_3
    };

    using Mac = std::array<uint8_t, N_OCTETS>;

    Ethernet();

    Ethernet & operator = (const Ethernet & other);

    Ethernet(Ethernet && other);

    Ethernet(ether_header * rawFrame);


    inline const Mac & getSourceMac() const { return MacSource; }
    inline const Mac & getDestinationMac() const { return MacDestination; }

    uint16_t getEtherType() const { return EtherType; } // returns Next underlying protocol
    uint16_t getEthernetLength() const { return getEtherType(); } // same as getEtherType()

    static bool hasNextProtocol(const Ethernet & value);

private:

    Mac MacSource, MacDestination;
    uint16_t EtherType;
    EthernetFrame frameType;

    // unused var
    size_t ethernet_length = -1;
};

#endif // ETHERNET_H
