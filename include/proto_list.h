#pragma once

#include "ethernet.h"
#include "proto.h"
#include "helpers.h"
#include "dns_utils.h"
#include <string>
#include <functional>
#include <QDebug>

#if _WIN32
    #include <WinSock2.h>
    #include <WS2tcpip.h>
#elif __linux__
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

enum protocol_t : uint8_t
{
    Unknown = 0,
    CurrentIPv4 = 1,
	CurrentIPv6,
	CurrentARP,
	CurrentTCP,
	CurrentUDP,
	CurrentICMP,
	CurrentDNS,
    CurrentTLS,
    CurrentHTTP,
};

enum layer_t : uint8_t
{
    Network,
    Transport,
    Application,
};

constexpr uint8_t
    ICMP_ECHO_REPLY = 0,
    ICMP_DEST_UNREACHABLE = 3,
    ICMP_SOURCE_QUENCH = 4,
    ICMP_REDIRECT = 5,
    ICMP_ECHO_REQUEST = 8,
    ICMP_TIME_EXCEEDED = 11,
    ICMP_PARAM_PROBLEM = 12,
    ICMP_TIMESTAMP = 13,
    ICMP_TIMESTAMP_REPLY = 14,
    ICMP_INFO_REQ = 15,
    ICMP_INFO_REP = 16;

constexpr int MAX_SUPPORTED_PROTOS = 7;

// ! BASE CLASS FOR ALL HOLDERS
class ProtocolHolder
{ 
public:
    ProtocolHolder(protocol_t t = Unknown) noexcept
    {
        type = t;
    }

    ProtocolHolder(const ProtocolHolder & other)
    {
        qDebug() << "Copy-constructor of ProtocolHolder";
    }
    ProtocolHolder(ProtocolHolder && other)
    {
        qDebug() << "ProtocolHolder(ProtocolHolder && other)";
    }

    protocol_t GetType() { return type; }
    protocol_t GetType() const { return type; }


    virtual bool isIPv4() const { return false; }
    virtual bool isIPv6() const { return false; }
    virtual bool isTCP() const { return false; }
    virtual bool isUDP() const { return false; }
    virtual bool isICMP() const { return false; }
    virtual bool isARP() const { return false; }
    virtual bool isDNS() const { return false; }

    template<typename T>
    T* as() {
        return dynamic_cast<T*>(this);
    }

    template<typename T>
    const T* as() const {
        return dynamic_cast<const T*>(this);
    }

    virtual ~ProtocolHolder() = default;

private:
    protocol_t type;
};


class IPv4Holder : public ProtocolHolder
{
public:
    IPv4Holder(const ip * realValue) : ProtocolHolder(CurrentIPv4)
    {
        ip_vhl   =	realValue->ip_vhl;
        ip_id    =	realValue->ip_id;
        ip_ttl   =	realValue->ip_ttl;
        ip_p     =	realValue->ip_p;
        ip_tos   =	realValue->ip_tos;
        ip_len =     ntohs(realValue->ip_len);
        ip_off =     ntohs(realValue->ip_off);
        ip_sum =     ntohs(realValue->ip_sum);

        source_address.resize(INET_ADDRSTRLEN);
        destination_address.resize(INET_ADDRSTRLEN);

        inet_ntop(AF_INET, &realValue->ip_dst, destination_address.data(), destination_address.size());
        inet_ntop(AF_INET, &realValue->ip_src, source_address.data(), source_address.size());
    }

    IPv4Holder(IPv4Holder && other)
    {
        this->ip_id = other.ip_id;
        this->ip_len = other.ip_len;
        this->ip_off = other.ip_off;
        this->ip_p = other.ip_p;
        this->ip_sum = other.ip_sum;
        this->ip_tos = other.ip_tos;
        this->ip_ttl = other.ip_ttl;
        this->ip_vhl = other.ip_vhl;

        this->source_address = std::move(other.source_address);
        this->destination_address = std::move(other.destination_address);
    }

    auto Version()
    {
        return IPV(ip_vhl);
    }
    auto IHL() const
    {
        return IP_HL(ip_vhl);
    }
    auto Identity()
    {
        return ip_id;
    }

    auto FragmentOffset()
    {
        return ip_off;
    }

    auto TTL()
    {
        return ip_ttl;
    }

    auto TotalLength()
    {
        return ip_len;
    }

    auto Checksum()
    {
        return ip_sum;
    }

    auto NextProtocol() const
    {
        return ip_p;
    }

    std::string_view SourceAddress() const
    {
        return source_address;
    }

    std::string_view DestinationAddress() const
    {
        return destination_address;
    }

    bool isIPv4() const override
    {
        return true;
    }

private:
    uint8_t  ip_vhl;
    uint8_t  ip_tos;		/* type of service */
    uint16_t ip_len;		/* total length */
    uint16_t ip_id;		/* identification */
    uint16_t ip_off;		/* fragment offset field */
    uint8_t  ip_ttl;		/* time to live */
    uint8_t  ip_p;			/* protocol */
    uint16_t ip_sum;		/* checksum */
    std::string source_address, destination_address;
};

class IPv6Holder : public ProtocolHolder
{
public:
    IPv6Holder(const ip6 * value) : ProtocolHolder(CurrentIPv6)
    {
        value_.vtf =         value->vtf;
        value_.nxt_hdr =     value->nxt_hdr;
        value_.hop =         value->hop;
        value_.payload_len = value->payload_len;

        std::memcpy(&value_.src_addr, &value->src_addr, sizeof(in6_addr));
        std::memcpy(&value_.dst_addr, &value->dst_addr, sizeof(in6_addr));
    }



    in6_addr    * GetSourceAddress() { return &value_.src_addr;}
    in6_addr    * GetDestinationAddress() {return &value_.dst_addr;}
    uint16_t    GetPayloadLength() { return value_.payload_len; }
    uint8_t     GetNextHeader() { return value_.nxt_hdr; }
    uint8_t     GetHopLimit() { return value_.hop; }


    bool isIPv6() const override { return true; }

private:
    ip6 value_;
};

class TCPHolder : public ProtocolHolder
{
public:

    TCPHolder(const tcphdr * value) : ProtocolHolder(CurrentTCP)
    {
        this->value.sport =           value->sport;
        this->value.dport =           value->dport;
        this->value.off_rsv =         value->off_rsv;
        this->value.flags =           value->flags;
        this->value.seq_num =         value->seq_num;
        this->value.ack_num =         value->ack_num;
        this->value.urgent_pointer =  value->urgent_pointer;
        this->value.window_size =     value->window_size;
        this->payload_size = 0;
    }

    auto SourcePort() { return value.sport; }
    auto DestinationPort() { return value.dport; }
    auto SequenceNumber() { return value.seq_num; }
    auto AcknowledgmentNumber() { return value.ack_num; }
    auto UrgentPointer() { return value.urgent_pointer; }
    auto WindowSize() { return value.window_size; }

    auto RawHeaderSize() const { return (value.off_rsv >> 4) & 15; }
    auto GetPayloadSize() const { return payload_size; }
    void SetPayloadSize(std::size_t siz) { this->payload_size = siz; }
    auto HeaderSize() const
    {
        return RawHeaderSize() * 4;
    }

    auto Flags() const { return value.flags; }

    bool isTCP() const override { return true; }

private:
    tcphdr value;
    std::size_t payload_size;
};

class UDPHolder : public ProtocolHolder
{
public:

    UDPHolder (const udphdr * value) : ProtocolHolder(CurrentUDP)
    {
        this->value.uh_dport =    value->uh_dport;
        this->value.uh_sport =    value->uh_sport;
        this->value.uh_sum =      value->uh_sum;
        this->value.uh_ulen =     value->uh_ulen;
    }

    auto SourcePort() const { return value.uh_sport; }
    auto DestinationPort() const { return value.uh_dport; }
    auto ChecksumSum()   { return value.uh_sum; }
    auto Length() { return value.uh_ulen; }
    auto HeaderSize() const { return sizeof(udphdr); }

    void SetPayloadLength(size_t payload_length)
    {
        this->payload_length = payload_length;
    }

    size_t GetPayloadLength() const
    {
        return payload_length;
    }

    bool isUDP() const override { return true; }

private:
    udphdr value;
    size_t payload_length;
};

class ICMPHolder : public ProtocolHolder
{
public:

    ICMPHolder(const ICMP * value) : ProtocolHolder(CurrentICMP)
    {
        this->value.type = value->type;
        this->value.chk_sum = value->chk_sum;
        this->value.code = value->code;
    }

    auto Type() const {return value.type; }
    auto CheckSum() { return value.chk_sum; }
    auto Code() { return value.code; }

    bool isICMP() const override { return false; }

private:
    ICMP value;
};

class ARPHolder : public ProtocolHolder
{
public:

    ARPHolder(const Arp * value) : ProtocolHolder(CurrentARP)
    {
        h_len =      value->h_len;
        p_len =      value->p_len;
        h_type =     ntohs(value->h_type);
        p_type =     ntohs(value->p_type);
        operation =  ntohs(value->operation);

        std::memcpy(source_mac, value->sender_mac, MAC_OCTETS);
        std::memcpy(target_mac, value->target_mac, MAC_OCTETS);
        std::memcpy(target_ip, value->target_laddr, sizeof(in_addr));
        std::memcpy(source_ip, value->sender_laddr, sizeof(in_addr));
    }


    auto Hardware() { return h_type; }
    auto ProtocolType() { return p_type; }
    auto HardwareSize() { return h_len; }
    auto ProtocolSize() { return p_len; }
    auto Operation() const { return operation; }
    const auto SourceIP() const { return &source_ip[0]; }
    const auto DestinationIP() const { return &target_ip[0]; }
    auto SourceMac() const { return &source_mac[0]; }
    auto DestinationMac() const { return &target_mac[0]; }
    bool isARP() const override { return true; }

private:
    uint8_t h_len;
    uint8_t p_len;
    uint16_t h_type;
    uint16_t p_type;
    uint16_t operation;
    uint8_t source_ip[4], target_ip[4];
    uint8_t source_mac[MAC_OCTETS], target_mac[MAC_OCTETS];
};

class DNSHolder : public ProtocolHolder
{
public:

    DNSHolder (const dnshdr * value) : ProtocolHolder(CurrentDNS)
    {
        this->value.flags =       value->flags;
        this->value.id =          value->id;
        this->questions_.reserve(ntohs(value->n_questions));
        this->answers_.reserve(ntohs(value->n_answers));

        std::ptrdiff_t qOffset = DNS_HEADER_SIZE, aOffset = 0;
        // firstly, parse questions section
        while (this->questions_.size() != this->questions_.capacity())
        {
            this->questions_.emplaceBack(DnsQuestion{});
            qOffset += ParseQuestion((const uint8_t*)(value + qOffset),
                                     &this->questions_.last());
        }

        aOffset = qOffset;

        // secondly, parse answers
        while(this->answers_.size() != this->answers_.capacity())
        {
            this->answers_.emplaceBack(DnsAnswer{});
            aOffset += ParseAnswer((const uint8_t*)(value + aOffset),
                        &this->answers_.last());
        }
    }

    auto Id() const { return value.id; }
    auto Flags() const { return value.flags; }

    auto QuestionsCount() const { return questions_.size(); }
    auto AnswerCount() const { return answers_.size(); }

    auto AuthorityCount() const { return 0; }
    auto AdditionalCount() const { return 0; }

    void SetMessageType(uint16_t qr) { this->qr = qr; }
    uint16_t GetMessageType(void) { return qr; }

    QString GetQueryDomain() const
    {
        return questions_.first().name;
    }

    bool isDNS() const override { return true; }
private:
    dnshdr value;            // dns header
    uint16_t qr;
    QList<DnsQuestion> questions_;
    QList<DnsAnswer> answers_;
};


class ProtocolHolderFactory
{
public:

    static ProtocolHolder * CreateNewV4(const uint8_t * data)
    {
        return new IPv4Holder {reinterpret_cast<const ip*>(data)};
    }

    static ProtocolHolder * CreateNewV6(const uint8_t * data)
    {
        return new IPv6Holder((const ip6*)data);
    }

    static ProtocolHolder * CreateNewUdp(const uint8_t * data)
    {
        return new UDPHolder((const udphdr*)data);
    }

    static ProtocolHolder * CreateNewIcmp(const uint8_t * data)
    {
        return new ICMPHolder((const ICMP*)data);
    }

    static ProtocolHolder * CreateNewDns(const uint8_t * data)
    {
        return new DNSHolder((const dnshdr*)data);
    }

    static ProtocolHolder * CreateNewArp(const uint8_t * data)
    {
        return new ARPHolder((const Arp*)data);
    }

    static ProtocolHolder * CreateNewTcp(const uint8_t * data)
    {
        return new TCPHolder((const tcphdr*)data);
    }
};

class Packet
{
public:
    Packet() : ethernet(), id{}, receive_time{}, alternative_time{},
      actual_len{}, capture_len{}, protocols{}
    {}
    Packet(Packet && other)
    {
        this->id = other.id;
        this->receive_time = other.receive_time;
        this->alternative_time = other.alternative_time;
        this->actual_len = other.actual_len;
        this->capture_len = other.capture_len;
        this->protocols = std::move(other.protocols);
        this->ethernet = std::move(other.ethernet);
    }

    Packet(const Packet & other) = delete;

    void SetId(int id)
    {
        this->id = id;
    }
    void SetReceiveTime(uint64_t receive_time)
    {
        this->receive_time = receive_time;
    }
    void SetAlternativeTime(uint64_t altime)
    {
        this->alternative_time = altime;
    }
    void SetActualLen(uint64_t len)
    {
        this->actual_len = len;
    }
    void SetCaptureLen(uint64_t len)
    {
        this->capture_len = len;
    }

    int GetId() const {return this->id; }
    std::uint64_t GetReceiveTime() const {return this->receive_time; }
    std::uint64_t GetAlternativeTime( ) const { return this->alternative_time; }
    std::uint64_t GetActualLen() const
    {
        return this->actual_len;
    }
    std::uint64_t GetCaptureLen() { return this->capture_len; }

    void AddLayer(ProtocolHolder * value)
    {
        protocols.emplace_back(value);
    }

    const ProtocolHolder * GetLayer(layer_t type_of) const
    {
        switch (type_of)
        {
            case Network:
                return getNetworkLayer();
            case Transport:
                return getTransportLayer();
            case Application:
                return getApplicationLayer();
        }

        return nullptr;
    }

    ProtocolHolder * GetLayer(layer_t type_of) {
        switch (type_of)
        {
            case Network:
                return const_cast<ProtocolHolder*>(getNetworkLayer());
            case Transport:
                return const_cast<ProtocolHolder*>(getTransportLayer());
            case Application:
                return const_cast<ProtocolHolder*>(getApplicationLayer());
        }

        return nullptr;
    }


    const ProtocolHolder & Last() const {
        return *(protocols.back().get());
    }

    const bool IsProtosEmpty() const
    {
        return protocols.empty();
    }

    // ETHERNET
    void SetEthernet(Ethernet && value)
    {
        ethernet = std::move(value);
    }
    const Ethernet & GetEthernet() const
    {
        return ethernet;
    }
    const Ethernet & GetEthernet()
    {
        return ethernet;
    }

    // LAYER PROPERTIES

    std::uint32_t GetNetworkHeaderSize()
    {
        auto proto = getNetworkLayer();
        if (!proto) {
            return 0;
        }

        // yet 4 version only is supported
        switch (proto->GetType()) {
        case CurrentIPv4: return proto->as<IPv4Holder>()->IHL() * 4;
        }

        return 0;
    }
    std::uint32_t GetTransportHeaderSize()
    {
        const auto proto = getTransportLayer();
        if (!proto) return 0;
        switch (proto->GetType()) {
        case CurrentTCP: return proto->as<TCPHolder>()->HeaderSize();
        case CurrentUDP: return proto->as<UDPHolder>()->HeaderSize();
        }

        return 0;
    }

private:
    int id;
    std::uint64_t alternative_time;
    std::uint64_t receive_time;
    std::uint64_t actual_len;
    std::uint64_t capture_len;
    Ethernet ethernet;

    std::vector<std::unique_ptr<ProtocolHolder>> protocols;

    const ProtocolHolder * getNetworkLayer() const
    {
        for (auto i = protocols.cbegin(); i != protocols.cend(); i++)
        {
            if (i->get()) {
                switch (i->get()->GetType())
                {
                    case CurrentIPv4:
                    case CurrentIPv6:
                    case CurrentARP:
                        return i->get();
                }
            }
        }

        return nullptr;
    }

    const ProtocolHolder * getTransportLayer() const
    {
        for (auto i = protocols.cbegin(); i != protocols.cend(); i++)
        {
            switch ((*i).get()->GetType())
            {
                case CurrentTCP:
                case CurrentUDP:
                    return (*i).get();
            }
        }

        return nullptr;
    }

    const ProtocolHolder * getApplicationLayer() const
    {
        for (auto i = protocols.cbegin(); i != protocols.cend(); i++)
        {
            switch ((*i).get()->GetType())
            {
                case CurrentHTTP:
                case CurrentDNS:
                    return (*i).get();
            }
        }

        return nullptr;
    }
};


class ProtocolUtility
{
public:
    static QString NameOfProtocol(const ProtocolHolder & proto)
    {
        switch (proto.GetType()) {
            case CurrentIPv4: {
                return "IPv4";
            } case CurrentIPv6: {
                return "IPv6";
            } case CurrentICMP: {
                return "ICMP";
            } case CurrentARP: {
                return "ARP";
            } case CurrentTCP: {
                return "TCP";
            } case CurrentUDP: {
                return "UDP";
            } case CurrentDNS: {
                return "DNS";
            } case CurrentHTTP: {
                return "HTTP";
            }
        }

        return "unknown";
    }

    static QString IpAsString(const uint32_t ip)
    {
        QString res;
        int shift = 24;
        for (; shift > 0;) {
            res += QString("%1.").arg((ip >> shift) & 255);
            shift -= 8;
        }

        res.removeLast();
        return res;
    }

    static QString IpAsString(const in_addr* addr)
    {
        char ip_buf[V4_BUF_SIZE_MAX];
        inet_ntop(AF_INET, addr, ip_buf, V4_BUF_SIZE_MAX);
        return ip_buf;
    }

    static QString IpAsString(const uint8_t * addr)
    {
        return IpAsString((const in_addr*)(addr));
    }

    static QString MacAsString(const uint8_t * mac) {
        char buf[MAC_MAX_LEN];
        std::snprintf(buf, MAC_MAX_LEN, MAC_FMT,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]);

        return buf;
    }

    static QString DescOfProtocol(const ProtocolHolder & proto)
    {
        QString message;
        QTextStream message_stream {&message};
        switch (proto.GetType()) {
        case CurrentTCP: {
            const auto tcp = proto.as<TCPHolder>();
            const auto flg = tcp->Flags();
            message_stream << "[" << QString((flg & TH_SYN) ? "SYN" : "") << ",";
            message_stream << QString((flg & TH_ACK) ? "ACK" : "" ) << ",";
            message_stream << QString((flg & TH_FIN) ? "FIN" : "" )<< ",";
            message_stream << QString((flg & TH_PUSH) ? "PUSH" : "" )<< ",";
            message_stream << QString((flg & TH_RST) ? "RST" : "" ) << ",";
            message_stream << QString((flg & TH_URG) ? "URG" : "" ) << "]";
            break;
        } case CurrentUDP: {
            const auto udp = proto.as<UDPHolder>();
            message_stream << QString("%1 -> %2 / %3 байт")
                              .arg(udp->SourcePort())
                              .arg(udp->DestinationPort())
                              .arg(udp->GetPayloadLength());
            break;
        } case CurrentDNS: {
            const auto dns = proto.as<DNSHolder>();
            message_stream << QString("q = %1, a = %2, AA = %3, AAD = %4 for name: ")
                                .arg(dns->QuestionsCount())
                                .arg(dns->AnswerCount())
                                .arg(dns->AuthorityCount())
                                .arg(dns->AdditionalCount());

            message_stream << QString("%1 fulfilled with status: ").arg(dns->GetQueryDomain());

            switch (dns->Flags() & DNS_FLAGS_RCODE_MASK) {
                case DNS_RCODE_NOERROR: {
                    message_stream << "OK";
                    break;
                } case DNS_RCODE_NXDOMAIN: {
                    message_stream << "No such name";
                    break;
                } case DNS_RCODE_FORMERR: {
                    message_stream << "Format error";
                    break;
                } case DNS_RCODE_REFUSED: {
                    message_stream << "Query Refused";
                    break;
                } case DNS_RCODE_SFAIL: {
                    message_stream << "Server failure";
                    break;
                } case DNS_RCODE_NIMPL: {
                    message_stream << "Not implemented";
                    break;
                }
            }
            break;
        } case CurrentARP: {
            const auto arp = proto.as<ARPHolder>();
            if (arp->Operation() == ARP_REQ_TYPE) {
                message_stream << "ARP (REQ) from " << ProtocolUtility::IpAsString(arp->SourceIP()) << " to TELL MAC for " << ProtocolUtility::IpAsString(arp->DestinationIP());
            } else {
                message_stream << "ARP (REPLY) client ";
                message_stream << ProtocolUtility::IpAsString(arp->SourceIP());
                message_stream << " has ";
                message_stream << ProtocolUtility::MacAsString(arp->SourceMac());
            }

            break;
        } case CurrentICMP: {
            const auto icmp = proto.as<ICMPHolder>();
            switch (icmp->Type()) {
            case ICMP_ECHO_REPLY: {
                message_stream << "Echo reply";
            }
            case ICMP_ECHO_REQUEST: {
                message_stream << "Echo request";
                break;
            }
            }

            break;
        }
        }

        return message;
    }

};
