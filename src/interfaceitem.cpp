#include "interfaceitem.h"
#include <cstring>


InterfaceItem::InterfaceItem(pcap_if_t *source_device)
{
    name = source_device->name;
    description = source_device->description;

    flags = source_device->flags;
    devType = DeviceType::Unknown;

    if (flags & PCAP_IF_WIRELESS)
        devType = DeviceType::Wireless;
    else if (flags & PCAP_IF_LOOPBACK)
        devType = DeviceType::Loopback;
    else if (!(flags & PCAP_IF_WIRELESS) && !(flags & PCAP_IF_LOOPBACK))
        devType = DeviceType::Ethernet;
    else devType = DeviceType::Other;

    pcap_addr * addr = source_device->addresses;
    while (addr)
    {
        addresses.emplace_back(addr);
        addr = addr->next;
    }

}

InterfaceItem::InterfaceItem(InterfaceItem &&other)
{
    name = std::move(other.name);
    description = std::move(other.description);
    addresses = std::move(other.addresses);
    flags = other.flags;
    devType = other.devType;
}

bool InterfaceItem::isRunning() const
{
    return (flags & PCAP_IF_RUNNING);
}

DeviceType InterfaceItem::GetType() const
{
    return devType;
}

QString InterfaceItem::GetName() const
{
    return name;
}

QString InterfaceItem::GetDescription() const
{
    return description;
}

QString InterfaceItem::GetFriendlyName() const
{
#ifdef __linux__
    return name;
#else
    return friendly_name;
#endif
}

void InterfaceItem::SetFriendlyName(const QString &value)
{
    friendly_name = value;
}

InterfaceItem::ConstIteratorType InterfaceItem::FirstAddress() const
{
    return addresses.cbegin();
}

InterfaceItem::ConstIteratorType InterfaceItem::LastAddress() const
{
    return addresses.cend();
}

uint32_t InterfaceItem::GetFlags() const
{
    return flags;
}

InterfaceItem::InterfaceAddress::InterfaceAddress(const pcap_addr *src_addr)
{
    hasAddr = false;
    hasMask = false;
    hasBroad = false;
    hasDst = false;

    if (src_addr->addr)
    {
        hasAddr = true;
        std::memcpy(&this->addr, src_addr->addr, sizeof(sockaddr));
    }

    if (src_addr->netmask)
    {
        hasMask = true;
        std::memcpy(&this->netmask, src_addr->netmask, sizeof(sockaddr));
    }

    if (src_addr->broadaddr)
    {
        hasBroad = true;
        std::memcpy(&this->broadaddr, src_addr->broadaddr, sizeof(sockaddr));
    }

    if (src_addr->dstaddr)
    {
        hasDst = true;
        std::memcpy(&this->dstaddr, src_addr->dstaddr, sizeof(sockaddr));
    }
}

const sockaddr *InterfaceItem::InterfaceAddress::getAddr() const
{
    return &addr;
}

const sockaddr *InterfaceItem::InterfaceAddress::getNetMask() const
{
    return &netmask;
}

const sockaddr *InterfaceItem::InterfaceAddress::getBroadAddr() const
{
    return &broadaddr;
}

const sockaddr *InterfaceItem::InterfaceAddress::getDstAddr() const
{
    return &dstaddr;
}

bool InterfaceItem::InterfaceAddress::HasAddress() const
{
    return hasAddr;
}

bool InterfaceItem::InterfaceAddress::HasNetmask() const
{
    return hasMask;
}

bool InterfaceItem::InterfaceAddress::HasBroadcast() const
{
    return hasBroad;
}

bool InterfaceItem::InterfaceAddress::HasDestination() const
{
    return hasDst;
}
