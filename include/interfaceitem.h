#ifndef INTERFACEITEM_H
#define INTERFACEITEM_H

#include <pcap/pcap.h>
#include <cstdint>
#include <QList>
#include <QString>

#if defined(_WIN32)
#include <iphlpapi.h>
#endif

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
    bool            isRunning() const;
    DeviceType      GetType() const;
    QString         GetName() const;
    QString         GetDescription() const;
    QString         GetFriendlyName() const;
    void            SetFriendlyName(const QString & fname);

    std::uint32_t GetFlags() const;

    class InterfaceAddress
    {
    public:
        InterfaceAddress(const pcap_addr *);
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


    using AddressList = QList<InterfaceAddress>;
    using ConstIteratorType = AddressList::const_iterator;


    ConstIteratorType FirstAddress() const;
    ConstIteratorType LastAddress() const;

private:
    QString         friendly_name;
    QString         name;
    QString         description;
    AddressList     addresses;
    std::uint32_t   flags;
    DeviceType      devType;


};

#endif // INTERFACEITEM_H
