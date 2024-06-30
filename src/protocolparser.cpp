#include "protocolparser.h"
#include "dns_utils.h"
#include <QWidget>
#include "helpers.h"
#include "proto_list.h"
#include "httpparser.h"

void ProtocolParser::ParseIP4(Packet * packet, const uint8_t * data)
{
    auto holder_value = ConstructHolder(packet,data, CurrentIPv4);
    packet->push_back(&holder_value);
}

void ProtocolParser::ParseIP6(Packet * packet, const uint8_t * data)
{
    auto holder_value = ConstructHolder(packet,data, CurrentIPv6);
    packet->push_back(&holder_value);
}

void ProtocolParser::ParseARP(Packet * packet, const uint8_t * data)
{
    auto holder_value = ConstructHolder(packet,data, CurrentARP);
    packet->push_back(&holder_value);
}






void ProtocolParser::ParseTCP(FrameInfo * frame_src, const uint8_t * data)
{
    auto holder_value = ConstructHolder(frame_src->p_ref, data, CurrentTCP);
    frame_src->p_ref->push_back(&holder_value);
}

void ProtocolParser::ParseUDP(FrameInfo * frame_src, const uint8_t * data)
{
    auto holder_value = ConstructHolder(frame_src->p_ref, data, CurrentUDP);
    frame_src->p_ref->push_back(&holder_value);
}

void ProtocolParser::ParseICMP(FrameInfo * frame_src, const uint8_t * data)
{
    auto holder_value = ConstructHolder(frame_src->p_ref, data, CurrentICMP);
    frame_src->p_ref->push_back(&holder_value);
}

void ProtocolParser::ParseDNS(FrameInfo * frame_src, const uint8_t * data)
{
    auto holder_value = ConstructHolder(frame_src->p_ref, data, CurrentDNS);
    frame_src->p_ref->push_back(&holder_value);
}

void ProtocolParser::ParseHTTP(FrameInfo * frame_src, const uint8_t * data)
{
    auto holder_value = ConstructHolder(frame_src->p_ref, data, CurrentHTTP);
    frame_src->p_ref->push_back(&holder_value);
}


ProtocolHolder *ConstructHolder(Packet * pkt,const void * data, protocol_t type)
{
    auto inst = new ProtocolHolder();
    inst->next = nullptr;
    switch (type)
    {
    case CurrentIPv4:
    {
        inst->IP4_header = *((ip*)(const uint8_t*)data);
        inst->type = type;
        break;
    }
    case CurrentIPv6:
    {
        inst->IP6_header = *((ip6*)(const uint8_t*)data);
        inst->type = type;
        break;
    }
    case CurrentARP:
    {
        inst->arp_header = *((Arp*)(const uint8_t*)data);
        inst->type = type;
        break;
    }

    case CurrentTCP:
    {
        inst->tcp_header = *((tcphdr*)(const uint8_t*)data);
        inst->type = type;
        break;
    }

    case CurrentUDP:
    {
        inst->udp_header = *((udphdr*)(const uint8_t*)data);
        inst->type = type;
        break;
    }

    case CurrentICMP:
    {

        auto nodeLast = pkt->Last();
        assert(nodeLast->type == CurrentIPv4);
        inst->icmp_header = ICMPHolder::constructFromRaw((const uint8_t*)data, nodeLast->IP4_header.ExtractTotalLength());
        inst->type = type;
        break;
    }
    case CurrentDNS:
    {
        const uint8_t* dns_data_begin = (const uint8_t*)(data);
        inst->dns_header = *((dnshdr*)dns_data_begin);
        DNSHolder * tmp = &inst->dns_header;

        uint16_t flags = tmp->GetFLAGS();
        inst->dns_header.SetMessageType(flags & DNS_FLAGS_QR_MASK);



        uint16_t q_count = tmp->GetNQ();
        uint16_t a_count = tmp->GetNA();
        uint16_t msg_type = tmp->GetMessageType();
        if (msg_type == DNS_FLAGS_QR_REPLY)
        {
            auto rcode = flags & DNS_FLAGS_RCODE_MASK;


            size_t parsed_size = 0;

            if (q_count)
            {
                parsed_size = DNSHolder::parseAllQuestions(tmp, dns_data_begin, q_count);
            }

            switch (rcode)
            {
            case DNS_RCODE_NOERROR:
            {
                if (a_count)
                {
                    const uint8_t * a_section = dns_data_begin + DNS_HEADER_SIZE + parsed_size;

                    DNSHolder::parseAllAnswers(tmp, a_section, dns_data_begin, a_count);
                }
                break;
            }
            case DNS_RCODE_FORMERR:
            {
                if (a_count)
                {
                    const uint8_t * a_section = dns_data_begin + DNS_HEADER_SIZE + parsed_size;
                    DNSHolder::parseAllAnswers(tmp, a_section, dns_data_begin, a_count);
                }
                break;
            }
            case DNS_RCODE_SFAIL:
            {
                if (a_count)
                {
                    const uint8_t * a_section = dns_data_begin + DNS_HEADER_SIZE + parsed_size;
                    DNSHolder::parseAllAnswers(tmp, a_section, dns_data_begin, a_count);
                }
                break;
            }
            case DNS_RCODE_NXDOMAIN:
            {
                if (a_count)
                {
                    const uint8_t * a_section = dns_data_begin + DNS_HEADER_SIZE + parsed_size;
                    DNSHolder::parseAllAnswers(tmp, a_section, dns_data_begin, a_count);
                }
                break;
            }
            case DNS_RCODE_NIMPL:
            {
                if (a_count)
                {
                    const uint8_t * a_section = dns_data_begin + DNS_HEADER_SIZE + parsed_size;
                    DNSHolder::parseAllAnswers(tmp, a_section, dns_data_begin, a_count);
                }
                break;
            }
            case DNS_RCODE_REFUSED:
            {
                if (a_count)
                {
                    const uint8_t * a_section = dns_data_begin + DNS_HEADER_SIZE + parsed_size;
                    DNSHolder::parseAllAnswers(tmp, a_section, dns_data_begin, a_count);
                }
                break;
            }
            }
        }
        else
        {
            if (q_count)
            {
                tmp->AllocateQuestions();
                DnsQuestion * questions_ref = tmp->GetQuestions();

                int index = 0;
                ParseQuestion(q_count, dns_data_begin, &questions_ref[index]);
            }
        }

        inst->type = type;
        break;
    }

    case CurrentHTTP:
    {
        inst->type = type;
        break;
    }

    }
    return inst;
}



int GetPayloadSize(ProtocolHolder * net_value, uint16_t nethdrsz, uint16_t trshdrsz, protocol_t type)
{
    int write_size = 0;
    switch (type)
    {
    case CurrentIPv4:
    {
        write_size = (net_value->IP4_header.ExtractTotalLength()) - (nethdrsz + trshdrsz);
        break;
    }
    case CurrentIPv6:
    {

        break;
    }
    default:
        break;
    }
    return write_size;
}

ProtocolHolder *GetProtoOfType(ProtocolHolder ** head, protocol_t required)
{
    ProtocolHolder * itr = (*head);
    while (itr->next)
    {
        if (itr->type == required) return itr;
        itr = itr->next;
    }

    return nullptr;
}

ProtocolHolder *GetNetLayerProto(ProtocolHolder ** head)
{
    ProtocolHolder * itr = (*head);
    assert(itr != nullptr);

    while (itr)
    {
        switch (itr->type)
        {
            case CurrentIPv4:
            case CurrentIPv6:
            case CurrentARP:
            {
                return itr;
            }
        }
        itr = itr->next;
    }

    return nullptr;
}

ProtocolHolder *GetTransportLayerProto(ProtocolHolder ** head)
{
    ProtocolHolder * itr = (*head);
    while (itr)
    {
        switch (itr->type)
        {
        case CurrentTCP:
        case CurrentUDP:
        case CurrentICMP:
        {
            return itr;
        }
        }

        itr = itr->next;
    }
    return nullptr;
}
