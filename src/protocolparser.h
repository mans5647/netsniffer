#ifndef PROTOCOLPARSER_H
#define PROTOCOLPARSER_H
#include "proto_list.h"

class ProtocolParser
{
public:
    static void ParseIP4(Packet*,       const uint8_t*);
    static void ParseIP6(Packet*,       const uint8_t*);
    static void ParseARP(Packet*,       const uint8_t*);


    static void ParseTCP(FrameInfo*,    const uint8_t*);
    static void ParseUDP(FrameInfo*,    const uint8_t*);
    static void ParseICMP(FrameInfo*,   const uint8_t*);
    static void ParseDNS(FrameInfo*,        const uint8_t*);
    static void ParseHTTP(FrameInfo *, const uint8_t*);
};

ProtocolHolder *ConstructHolder(Packet*,const void*, protocol_t);
int GetPayloadSize(ProtocolHolder*, uint16_t, uint16_t, protocol_t);

ProtocolHolder * GetProtoOfType(ProtocolHolder**, protocol_t);
ProtocolHolder * GetNetLayerProto(ProtocolHolder**);
ProtocolHolder * GetTransportLayerProto(ProtocolHolder**);



#endif // PROTOCOLPARSER_H
