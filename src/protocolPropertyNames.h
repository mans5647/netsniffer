#ifndef PROTOCOLPROPERTYNAMES_H
#define PROTOCOLPROPERTYNAMES_H


enum class ether_property_t
{
    SenderMac,
    ReceiverMac,
    NextProtocol
};


enum class ip_property_t
{
    SourceIP,
    DestinationIP,
    Version,
    Length,
    ServiceType,
    TotalLength,
    Id,
    Offset,
    Ttl,
    Protocol,
    CheckSum
};


#endif // PROTOCOLPROPERTYNAMES_H
