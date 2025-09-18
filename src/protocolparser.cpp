#include "protocolparser.h"

std::optional<Packet> ProtocolParser::Parse(int frame_id, pcap_pkthdr* header, const uint8_t* data)
{
    Packet packet;
    std::uint32_t net_header_size{}, transport_header_size{};
    std::size_t payload_size = 0;
    ParseError err = ParseError::ParseNoError;

    packet.SetId(frame_id);
    packet.SetActualLen(header->len);
    packet.SetCaptureLen(header->caplen);
    packet.SetReceiveTime(header->ts.tv_sec);
    packet.SetAlternativeTime(header->ts.tv_usec);

    Ethernet ethernet{reinterpret_cast<const ether_header*>(data)};

    packet.SetEthernet(std::move(ethernet));


    if (!packet.GetEthernet().hasNextProtocol()) {
        return packet;
    }

    err = parseNetworkLayer(packet, ToNetworkLayer(data));

    if (err != ParseError::ParseNoError) {
        return std::nullopt;
    }

    net_header_size = packet.GetNetworkHeaderSize();

    err = parseTransportLayer(packet, ToTransportLayer(data, net_header_size));

    if (err != ParseError::ParseNoError) {

        if (err == ParseError::ParseErrorFinish) {
            return packet;
        }

        return std::nullopt;
    }

    // set payload size to UDP or TCP

    // first, get layers
    ProtocolHolder * net_proto = packet.GetLayer(Network);
    ProtocolHolder * tran_proto = packet.GetLayer(Transport);
    if (net_proto->GetType() == CurrentIPv4) {
        payload_size = net_proto->as<IPv4Holder>()->TotalLength() -
                (net_header_size + transport_header_size);
    }

    if (tran_proto) {
        if (tran_proto->GetType() == CurrentTCP) {
            tran_proto->as<TCPHolder>()->SetPayloadSize(payload_size);
        } else if (tran_proto->GetType() == CurrentUDP) {
            tran_proto->as<UDPHolder>()->SetPayloadLength(payload_size);
        }
    }


    return packet;
}

ParseError ProtocolParser::parseNetworkLayer(Packet & packet, const uint8_t * data)
{
    switch (packet.GetEthernet().EtherType()) {
        case H_PROTO_ARP: {
            packet.AddLayer(ProtocolHolderFactory::CreateNewArp(data));
            break;
        }
        case H_PROTO_IP4: {
            packet.AddLayer(ProtocolHolderFactory::CreateNewV4(data));
            break;
        }
        case H_PROTO_IP6: {
            packet.AddLayer(ProtocolHolderFactory::CreateNewV6(data));
            break;
        }
    }

    return ParseError::ParseNoError;
}

ParseError ProtocolParser::parseTransportLayer(Packet & packet, const uint8_t * data)
{
    const ProtocolHolder * proto = packet.GetLayer(Network);
    if (proto) {
        switch (proto->GetType())
        {
            case CurrentIPv4: {
                const IPv4Holder * ipv4 = proto->as<IPv4Holder>();

                if (ipv4) {
                    switch (ipv4->NextProtocol()) {
                    case TCP_NEXT: {
                        packet.AddLayer(ProtocolHolderFactory::CreateNewTcp(data));
                        break;
                    } case UDP_NEXT: {
                        packet.AddLayer(ProtocolHolderFactory::CreateNewUdp(data));
                        break;
                    } case ICMP_NEXT: {
                        packet.AddLayer(ProtocolHolderFactory::CreateNewIcmp(data));
                        break;
                    }
                    }
                } else return ParseError::ParseInternalError;

            break;
        } case CurrentIPv6: {
            return ParseError::ParseErrorTempUnsupport;
        } case CurrentARP: {
            return ParseError::ParseErrorFinish;
        }
        }
    }

    return ParseError::ParseNoError;
}

ParseError ProtocolParser::parseApplicationLayer(Packet & packet, const uint8_t * data)
{
    return ParseError::ParseNoError;
}

// int GetPayloadSize(ProtocolHolder * net_value, uint16_t nethdrsz, uint16_t trshdrsz, protocol_t type)
// {
//     int write_size = 0;
//     switch (type)
//     {
//     case CurrentIPv4:
//     {
//         write_size = (net_value->IP4_header.ExtractTotalLength()) - (nethdrsz + trshdrsz);
//         break;
//     }
//     case CurrentIPv6:
//     {

//         break;
//     }
//     default:
//         break;
//     }
//     return write_size;
// }


// ProtocolHolder *GetNetLayerProto(ProtocolHolder ** head)
// {
//     ProtocolHolder * itr = (*head);
//     assert(itr != nullptr);

//     while (itr)
//     {
//         switch (itr->type)
//         {
//             case CurrentIPv4:
//             case CurrentIPv6:
//             case CurrentARP:
//             {
//                 return itr;
//             }
//         }
//         itr = itr->next;
//     }

//     return nullptr;
// }

// ProtocolHolder *GetTransportLayerProto(ProtocolHolder ** head)
// {
//     ProtocolHolder * itr = (*head);
//     while (itr)
//     {
//         switch (itr->type)
//         {
//         case CurrentTCP:
//         case CurrentUDP:
//         case CurrentICMP:
//         {
//             return itr;
//         }
//         }

//         itr = itr->next;
//     }
//     return nullptr;
// }
