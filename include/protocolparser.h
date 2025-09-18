#ifndef PROTOCOLPARSER_H
#define PROTOCOLPARSER_H

#include "proto_list.h"
#include <pcap/pcap.h>

enum class ParseError
{
    ParseNoError,
    ParseErrorAtLink,
    ParseErrorAtNet,
    ParseErrorAtTransport,
    ParseErrorAtApp,
    ParseErrorUnsupported,
    ParseInternalError,
    ParseTransportLayerNotExists,
    ParseErrorTempUnsupport,
    ParseErrorFinish,
};

// parses raw data from PCAP, and returns Packet instance class
class ProtocolParser
{
public:
    std::optional<Packet> Parse(int, pcap_pkthdr*, const uint8_t*);
private:
    ParseError      error;
    ParseError parseNetworkLayer(Packet &, const uint8_t *);
    ParseError parseTransportLayer(Packet &, const uint8_t *);
    ParseError parseApplicationLayer(Packet &, const uint8_t *);

    const uint8_t* ToNetworkLayer(const uint8_t* data_begin)
    {
        return data_begin + ETH_HEADER_SIZE;
    }
    const uint8_t* ToTransportLayer(const uint8_t* data_begin, std::ptrdiff_t net = 0)
    {
        return data_begin + ETH_HEADER_SIZE + net;
    }
    const uint8_t* ToApplicationLayer(const uint8_t* data_begin, std::ptrdiff_t net = 0, std::ptrdiff_t tran = 0)
    {
        return data_begin + ETH_HEADER_SIZE + net + tran;
    }

};
#endif // PROTOCOLPARSER_H
