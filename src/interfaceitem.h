#ifndef INTERFACEITEM_H
#define INTERFACEITEM_H

#include <pcap/pcap.h>
#include <cstdint>
#include <QByteArray>
#include <QString>
#include <iphlpapi.h>

enum class DeviceType
{
    Unknown,
    Wireless,
    Ethernet,
    Loopback,
    Other
};



class InterfaceItem
{
public:


    InterfaceItem(pcap_if_t * source_device);
    InterfaceItem(InterfaceItem && other);
    bool is_running() const;
    DeviceType getType() const;
    const QByteArray & getName() const;
    const QByteArray & getDescription() const;
    QString getFriendlyName() const;
    void setFriendlyName(const QString & fname);

    std::uint32_t getFlags() const;

    class InterfaceAddress
    {
    public:
        InterfaceAddress(pcap_addr * src_addr);
        const sockaddr * getAddr()      const;
        const sockaddr * getNetMask()   const;
        const sockaddr * getBroadAddr() const;
        const sockaddr * getDstAddr()   const;

        bool HasAddress() const;
        bool HasNetmask() const;
        bool HasBroadcast() const;
        bool HasDestination() const;

    private:
        sockaddr addr;
        sockaddr netmask;
        sockaddr broadaddr;
        sockaddr dstaddr;
        bool hasAddr, hasMask, hasBroad, hasDst;
    };


    using AddressList = std::vector<InterfaceAddress>;
    using ConstIteratorType = AddressList::const_iterator;


    ConstIteratorType firstAddress() const;
    ConstIteratorType lastAddress() const;

private:
    QString friendly_name;
    QByteArray name;
    QByteArray description;
    AddressList addresses;
    std::uint32_t flags;
    DeviceType m_type;


};

#endif // INTERFACEITEM_H
