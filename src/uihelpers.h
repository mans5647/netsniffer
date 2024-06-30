#ifndef UIHELPERS_H
#define UIHELPERS_H

#include <QString>
#include <QTime>
#include <QTimeZone>
#include <ctime>
#include <cstdint>
#include "proto_list.h"

enum class Locale
{
    Ru,
    En
};

enum class PacketPropertyFrame
{
    FrameN,
    FrameUTCTime,
    FrameLocalTime,
    FrameEpochTime,
    FrameLen,
    FrameCapLen,
    FrameProtos,
};

enum class PacketPropertyIp
{
    Version,
    Hlen,
    DSCP,
    ECN,
    Total,
    Id,
    FlagsCommon,
    Flag1,
    Flag2,
    Flag3,
    Offset,
    Ttl,
    Proto,
    Checksum,
    Src,
    Dst,
};

enum class TypeOfValue {
    FrameProperty,
    IpProperty
};

struct ValueOfLocale
{
    TypeOfValue type;

    union {
        PacketPropertyFrame overview_prop;
        PacketPropertyIp ip_prop;
    } value;

};


QString getEthernetNextProtocolName(std::uint16_t);
QString getCurrentUTCTime();
QString getCurrentLocalTime();
QString getFormattedProtocolNames(const FrameInfo *);

QString getUTCFromTimeT(const time_t &);
QString getLocalFromTimeT(const time_t&);

const QString & getLastProtocol(const ProtocolHolder *);
const QString & getPacketInfo(ProtocolHolder *);
const QString &getFormattedAddress(void *, int);
const QString getNameOfKey(Locale, const ValueOfLocale&);


const QString getRussianLocaleParam(const ValueOfLocale &);

QString toHex(uint64_t);
QString getIPNextProtocol(uint8_t);
QString ipGetFlagsStr(bool ,bool, bool);
QString ipGetReservedStr(bool);


// ip flags utils
QString ipGetRStr(bool);
QString ipGetDFStr(bool);
QString ipGetMFStr(bool);

// arp utils
QString getARPHardwareType(int);
QString getARPProtocolType(int);
QString getARPOpcodeType(int);


// DNS utils

QString DnsStrType(uint16_t     __type);
QString DnsStrClass(uint16_t    __class);
QString DnsFmtFlag__query_type(uint16_t flags);
QString DnsFmtFlag__opcode(uint16_t flags);
QString DnsFmtFlags__is_auth(uint16_t flags);
QString DnsFmtFlags__is_trunc(uint16_t flags);
QString DnsFmtFlags__is_rd(uint16_t flags);
QString DnsFmtFlags_is_ra(uint16_t flags);
QString DnsFmtFlags__z(uint16_t flags);
QString DnsFmtFlags__rcode(uint16_t flags);


#endif // UIHELPERS_H
