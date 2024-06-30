#include "interfaceitem.h"
#include <cstring>


InterfaceItem::InterfaceItem(pcap_if_t *source_device)
{
    name = QByteArray(source_device->name, std::strlen(source_device->name));
    description = QByteArray(source_device->description, std::strlen(source_device->description));

    flags = source_device->flags;
    m_type = DeviceType::Unknown;

    if (flags & PCAP_IF_WIRELESS)
        m_type = DeviceType::Wireless;
    else if (flags & PCAP_IF_LOOPBACK)
        m_type = DeviceType::Loopback;
    else if (!(flags & PCAP_IF_WIRELESS) && !(flags & PCAP_IF_LOOPBACK))
        m_type = DeviceType::Ethernet;
    else m_type = DeviceType::Other;

    pcap_addr * node = source_device->addresses;
    while (node)
    {
        addresses.emplace_back(node);
        node = node->next;
    }

}

InterfaceItem::InterfaceItem(InterfaceItem &&other)
{
    name = std::move(other.name);
    description = std::move(other.description);
    addresses = std::move(other.addresses);
    flags = other.flags;
    m_type = other.m_type;
}

bool InterfaceItem::is_running() const
{
    return (flags & PCAP_IF_RUNNING);
}

DeviceType InterfaceItem::getType() const
{
    return m_type;
}

const QByteArray &InterfaceItem::getName() const
{
    return name;
}

const QByteArray &InterfaceItem::getDescription() const
{
    return description;
}

QString InterfaceItem::getFriendlyName() const
{
    return friendly_name;
}

void InterfaceItem::setFriendlyName(const QString &fname)
{
    friendly_name = fname;
}

InterfaceItem::ConstIteratorType InterfaceItem::firstAddress() const
{
    return addresses.cbegin();
}


InterfaceItem::ConstIteratorType InterfaceItem::lastAddress() const
{
    return addresses.cend();
}

uint32_t InterfaceItem::getFlags() const
{
    return flags;
}

InterfaceItem::InterfaceAddress::InterfaceAddress(pcap_addr *src_addr)
{
    sockaddr * addr_ = src_addr->addr;
    sockaddr * nmsk = src_addr->netmask;
    sockaddr * baddr = src_addr->broadaddr;
    sockaddr * dst = src_addr->dstaddr;
    hasAddr = false;
    hasMask = false;
    hasBroad = false;
    hasDst = false;

    if (addr_)
    {
        hasAddr = true;
        memcpy(&addr, addr_, sizeof(sockaddr));
    }
    if (nmsk)
    {
        hasMask = true;
        memcpy(&netmask, nmsk, sizeof(sockaddr));
    }
    if (baddr)
    {
        hasBroad = true;
        memcpy(&broadaddr, baddr, sizeof(sockaddr));
    }
    if (dst)
    {
        hasDst = true;
        memcpy(&dstaddr, dst, sizeof(sockaddr));
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
