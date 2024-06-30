#pragma once
#include "ethernet.h"
#include "proto.h"
#include "helpers.h"
#include "dns_utils.h"
#include <tuple>
#include <string>
#include <variant>
#include <QDebug>

template<typename ... types>
using values = std::tuple<types ...>;

class IPv4Holder
{
	
public:
    IPv4Holder() = default;


    IPv4Holder (const IPv4Holder & other)
    {
        this->operator =(other);
    }

    IPv4Holder & operator=(const IPv4Holder& other)
    {
        value.ip_vhl =	other.value.ip_vhl;
        value.ip_id =	other.value.ip_id;
        value.ip_sum =	other.value.ip_sum;
        value.ip_len =	other.value.ip_len;
        value.ip_src =	other.value.ip_src;
        value.ip_dst =	other.value.ip_dst;
        value.ip_ttl =	other.value.ip_ttl;
        value.ip_off =	other.value.ip_off;
        value.ip_p	=	other.value.ip_p;
        value.ip_tos =	other.value.ip_tos;

        std::copy(other.dst, other.dst + 32, dst);
        std::copy(other.src, other.src + 32, src);
        return *this;
    }


	IPv4Holder& operator=(const ip & __value)
	{
		value.ip_vhl =	__value.ip_vhl;
		value.ip_id =	__value.ip_id;
		value.ip_sum =	__value.ip_sum;
		value.ip_len =	__value.ip_len;
		value.ip_src =	__value.ip_src;
		value.ip_dst =	__value.ip_dst;
		value.ip_ttl =	__value.ip_ttl;
		value.ip_off =	__value.ip_off;
		value.ip_p	=	__value.ip_p;
		value.ip_tos =	__value.ip_tos;


        inet_ntop(AF_INET, &value.ip_src, src, 32);
        inet_ntop(AF_INET, &value.ip_dst, dst, 32);
        CorrectData();
		return *this;
	}
	auto ExtractVersion()
	{
		return IPV(value.ip_vhl);
	}
	auto ExtractIHL()
	{
		return IP_HL(value.ip_vhl);
	}
	auto ExtractIdentity()
	{
		return value.ip_id;
	}
	values<bool, bool, bool> ExtractFFlags()
    {
        auto flags = value.ip_off;
		return std::tuple<bool, bool, bool>((flags & IP_RF), (flags & IP_DF), (flags & IP_MF));
	}

	inline auto ExtractFragmentOffset()
	{
        return value.ip_off;
	}

	inline auto ExtractTTL()
	{
		return value.ip_ttl;
	}

	auto ExtractTotalLength()
	{
        return value.ip_len;
	}

	auto ExtractChecksum()
	{
        return value.ip_sum;
	}

	auto ExtractNextProto()
	{
		return value.ip_p;
	}

    auto ExtractSrcAddr()
    {
        return src;
    }
    auto ExtractDstAddr()
    {
        return dst;
    }

    void CorrectData()
    {
        value.ip_len = ntohs(value.ip_len);
        value.ip_id = ntohs(value.ip_id);
        value.ip_off = ntohs(value.ip_off);
        value.ip_sum = ntohs(value.ip_sum);
    }

    ~IPv4Holder() {}

private:
	ip value;
    char src[32];
    char dst[32];
};

class IPv6Holder
{
public:
    IPv6Holder() = default;
    IPv6Holder (const IPv6Holder & other)
    {
        this->operator =(other);
    }


    IPv6Holder & operator=(const IPv6Holder & other)
    {
        value.vtf =         other.value.vtf;
        value.nxt_hdr =     other.value.nxt_hdr;
        value.hop =         other.value.hop;
        value.payload_len = other.value.payload_len;

        memcpy(&value.src_addr, &other.value.src_addr, sizeof(in6_addr));
        memcpy(&value.dst_addr, &other.value.dst_addr, sizeof(in6_addr));

        return *this;
    }

    IPv6Holder & operator=(const ip6 &__ip_value)
    {
        value.vtf = __ip_value.vtf;
        value.nxt_hdr = __ip_value.nxt_hdr;
        value.hop = __ip_value.hop;
        value.payload_len = __ip_value.payload_len;

        memcpy(&value.src_addr, &__ip_value.src_addr, sizeof(in6_addr));
        memcpy(&value.dst_addr, &__ip_value.dst_addr, sizeof(in6_addr));

        CorrectData();
        return *this;
    }


    in6_addr * getSourceAddress()
    {
        return &value.src_addr;
    }

    in6_addr * getDestinationAddress()
    {
        return &value.dst_addr;
    }

    uint16_t getPayloadLen() { return value.payload_len; }
    uint8_t getNextHeader() { return value.nxt_hdr; }
    uint8_t getHopLimit() { return value.hop; }

    ~IPv6Holder() {}

private:
	ip6 value;

    void CorrectData()
    {
        value.vtf = ntohl(value.vtf);
        value.payload_len = ntohs(value.payload_len);
    }

};

class TCPHolder
{
public:


    TCPHolder() = default;
    TCPHolder (const TCPHolder& other)
    {
        this->operator =(other);
    }

    TCPHolder & operator= (const TCPHolder& other)
    {
        value.sport = other.value.sport;
        value.dport = other.value.dport;
        value.off_rsv = other.value.off_rsv;
        value.flags = other.value.flags;
        value.seq_num = other.value.seq_num;
        value.ack_num = other.value.ack_num;
        value.urgent_pointer = other.value.urgent_pointer;
        value.window_size = other.value.window_size;

        return *this;

    }


    TCPHolder & operator=(const tcphdr& other)
    {
        value.sport = other.sport;
        value.dport = other.dport;
        value.off_rsv = other.off_rsv;
        value.flags = other.flags;
        value.seq_num = other.seq_num;
        value.ack_num = other.ack_num;
        value.urgent_pointer = other.urgent_pointer;
        value.window_size = other.window_size;

        CorrectData();
        return *this;
    }

    auto ExtractSPort() { return value.sport; }
    auto ExtractDPort() { return value.dport; }
    auto ExtractSeqNum() { return value.seq_num; }
    auto ExtractAckNum() { return value.ack_num; }
    auto ExtractUrgentPtr() { return value.urgent_pointer; }
    auto ExtractWindSize() { return value.window_size; }

    auto ExtractRawHeaderSize() { return (value.off_rsv >> 4) & 15; }

    auto ExtractHeaderSize()
    {
        return ((value.off_rsv >> 4) & 15) * 4;
    }

    auto ExtractFlags() { return value.flags; }

    void SetPayloadLength(size_t payload_length)
    {
        this->payload_length = payload_length;
    }

    size_t GetPayloadLength()
    {
        return payload_length;
    }

    ~TCPHolder() {}

private:
	tcphdr value;
    void CorrectData()
    {
        value.sport = ntohs(value.sport);
        value.dport = ntohs(value.dport);
        value.seq_num = ntohl(value.seq_num);
        value.ack_num = ntohl(value.ack_num);
        value.window_size = ntohs(value.window_size);
        value.urgent_pointer = ntohs(value.urgent_pointer);
        value.chk_sum = ntohs(value.chk_sum);

    }

    size_t payload_length;

};

class UDPHolder
{
public:

    UDPHolder() = default;


    UDPHolder(const UDPHolder& other)
    {
        this->operator =(other);
    }


    UDPHolder & operator=(const UDPHolder& other)
    {
        value.uh_dport = other.value.uh_dport;
        value.uh_sport = other.value.uh_sport;
        value.uh_sum = other.value.uh_sum;
        value.uh_ulen = other.value.uh_ulen;
        payload_length = other.payload_length;
        return *this;
    }


    UDPHolder & operator=(const udphdr& other)
    {
        value.uh_dport  =    ntohs(other.uh_dport);
        value.uh_sport  =    ntohs(other.uh_sport);
        value.uh_sum    =    ntohs(other.uh_sum);
        value.uh_ulen   =    ntohs(other.uh_ulen);
        return *this;
    }

    auto ExtractSPort() { return value.uh_sport; }
    auto ExtractDPort() { return value.uh_dport; }
    auto ExtractSum()   { return value.uh_sum; }
    auto ExtractLen() { return value.uh_ulen; }
    auto GetHeaderSize() { return (uint16_t)sizeof(udphdr); }

    void SetPayloadLength(size_t payload_length)
    {
        this->payload_length = payload_length;
    }

    size_t GetPayloadLength()
    {
        return payload_length;
    }

    ~UDPHolder() {}
private:
	udphdr value;
    size_t payload_length;
};


#include <fstream>

class ICMPHolder
{
public:

    enum class ICMPMessageType
    {
        EchoReply = 0,
        DestinationUnreachable = 3,
        SourceQuench = 4,
        Redirect = 5,
        Echo = 8,
        TimeExceeded = 11,
        ParamProblem = 12,
        Timestamp = 13,
        TimestampReply = 14,
        InfoRequest = 15,
        InfoReply = 16
    };

    enum class ICMP_DuCode /* destination unreachable codes */
    {
        NetU = 0,
        HostU = 1,
        ProtoU = 2,
        PortU = 3,
        FNeeded = 4,
        SRCRouteFailed = 5
    };

    enum class ICMP_TimeExCode /* time exceeded codes */
    {
        TtlExceeded = 0,
        FragmentReassemblyExceed = 1
    };

    enum class ICMP_ParamProblemCode
    {
        PtrError = 0
    };

    enum class ICMP_SQCode
    {
        SQNull = 0
    };

    enum class ICMP_RedirectCode
    {
        RedirToNet = 0,
        RedirToHost = 1,
        RedirToTosNet = 2,
        RedirToTosHost = 3
    };

    enum class ICMP_EchoReplyCode
    {
        EchoNull = 0
    };

    enum class ICMP_TimestampCode
    {
        TimestampNull = 0
    };

    enum class ICMP_IFRequestReplyCode
    {
        IFNull = 0
    };


    using code_t = std::variant<ICMP_DuCode, ICMP_TimeExCode,
                                ICMP_ParamProblemCode,ICMP_SQCode,
                                ICMP_RedirectCode,ICMP_EchoReplyCode,
                                ICMP_TimestampCode, ICMP_IFRequestReplyCode>;


    using DataInetHeader =
    struct
    {
        IPv4Holder IPSection; // ip header
        uint64_t end_eigth_bytes; // + 8 bytes offset
    };

    using DataRaw = std::string;

    using IcmpData_t =
        std::variant<DataInetHeader, DataRaw>;


    ICMPHolder() : currentCode{} {}


    ICMPHolder(const ICMPHolder& other)
    {
        *this = other;
    }

    ICMPHolder & operator=(const ICMPHolder& other)
    {
        currentMsgType = other.currentMsgType;
        currentCode = other.currentCode;
        id = other.id;
        seq_num = other.seq_num;
        checkSum = other.checkSum;
        data = other.data;
        return *this;
    }



    ICMPHolder & operator=(const ICMP& other)
    {
        return *this;
    }

    ICMPHolder(uint8_t type, uint8_t code, uint16_t checksum,const uint8_t * dataBegin, size_t totalPacketSize)
    {
        currentMsgType = static_cast<ICMPMessageType>(type);
        int code_int = static_cast<int>(code);
        switch (currentMsgType)
        {
        case ICMPMessageType::DestinationUnreachable: currentCode = static_cast<ICMP_DuCode>(code_int); break;
        case ICMPMessageType::TimeExceeded: currentCode = static_cast<ICMP_TimeExCode>(code_int); break;
        case ICMPMessageType::ParamProblem: currentCode = static_cast<ICMP_ParamProblemCode>(code_int); break;
        case ICMPMessageType::SourceQuench: currentCode = static_cast<ICMP_SQCode>(code_int); break;
        case ICMPMessageType::Redirect: currentCode = static_cast<ICMP_RedirectCode>(code_int); break;
        case ICMPMessageType::Echo:
        case ICMPMessageType::EchoReply:
            currentCode = static_cast<ICMP_EchoReplyCode>(code_int); break;
        case ICMPMessageType::Timestamp:
        case ICMPMessageType::TimestampReply:
            currentCode = static_cast<ICMP_TimestampCode>(code_int); break;
        case ICMPMessageType::InfoRequest:
        case ICMPMessageType::InfoReply:
            currentCode = static_cast<ICMP_IFRequestReplyCode>(code_int); break;
        default:
            assert(false);
        }

        this->checkSum = checkSum;

        // data parsing
        switch (currentMsgType)
        {
        case ICMPMessageType::Echo:
        case ICMPMessageType::EchoReply:
        {

            uint16_t * id_ptr = (uint16_t*)dataBegin;
            uint16_t * seq_ptr = (uint16_t*)(dataBegin + 2);

            id = ntohs(*id_ptr);
            seq_num = ntohs(*seq_ptr);




            data = std::string();
            std::string & rawBuf = std::get<std::string>(data);

            const uint8_t * syms = (dataBegin + 4);
            int count = 0;
            while (std::isprint(*syms))
            {
                rawBuf += static_cast<char>(*syms);
                syms++;
            }


            break;
        }

        case ICMPMessageType::DestinationUnreachable:
        case ICMPMessageType::TimeExceeded:
        case ICMPMessageType::ParamProblem:
        case ICMPMessageType::SourceQuench:
        case ICMPMessageType::Redirect:

        {
            const uint8_t * hdr = (dataBegin + 32);

            data = DataInetHeader();
            DataInetHeader & dref = std::get<DataInetHeader>(data);

            ip* _ip_ptr = (ip*)(hdr);

            dref.IPSection = *_ip_ptr;
            dref.end_eigth_bytes = *(uint64_t*)(hdr + sizeof(ip));
            break;
        }

            /*
        case ICMPMessageType::Timestamp:
        case ICMPMessageType::TimestampReply:
        {
            break;
        }
            */

        case ICMPMessageType::InfoRequest:
        case ICMPMessageType::InfoReply:
        {
            uint16_t * id_ptr = (uint16_t*)dataBegin;
            uint16_t * seq_ptr = (uint16_t*)(dataBegin + 2);

            id = ntohs(*id_ptr);
            seq_num = ntohs(*seq_ptr);
            break;
        }

        }

    }




    ICMPMessageType getMessageType() { return currentMsgType; }
    code_t & getCode() { return currentCode; }
    uint16_t getChecksum() { return checkSum; }
    uint16_t getSequenceNum() { return seq_num; }
    uint16_t getID() { return id; }

    IcmpData_t & getData() { return data; }


    size_t getDataLength()
    {
        size_t index = data.index();

        if (index == 0)
        {
            return sizeof(ip) + 8;
        }
        else if (index == 1)
        {
            return std::get<1>(data).size();
        }

        return 0;
    }

    static ICMPHolder constructFromRaw(const uint8_t * rawData, size_t totalPacketSize)
    {
        ICMP * icmp_data = (ICMP*)rawData;
        icmp_data->chk_sum = ntohs(icmp_data->chk_sum);
        const uint8_t * dataBegin = (rawData + sizeof(ICMP));
        return ICMPHolder(icmp_data->type, icmp_data->code, icmp_data->chk_sum, dataBegin, totalPacketSize);
    }



private:
    ICMP value;
    ICMPMessageType currentMsgType;
    code_t currentCode;
    uint16_t checkSum;
    uint16_t id, seq_num;
    IcmpData_t data;

};

class DNSHolder
{
public:

    DNSHolder()
    {
        questions = nullptr;
        answers = nullptr;
    }

    DNSHolder(const DNSHolder& other)
    {
        this->operator =(other.value);
    }

    DNSHolder & operator= (const DNSHolder& other)
    {
        value.n_questions = other.value.n_questions;
        value.n_answers =   other.value.n_answers;
        value.n_addinfo =   other.value.n_addinfo;
        value.n_authority = other.value.n_authority;
        value.flags =       other.value.flags;
        value.id =          other.value.id;

        if (value.n_questions)
        {
            questions = new DnsQuestion[value.n_questions];
            DnsQuestion * from = other.GetQuestions();
            for (auto i = 0; i < value.n_questions; i++)
            {
                questions[i].name = (*from).name;
                questions[i].cl_name = (*from).cl_name;
                questions[i].type = (*from).type;
                from++;
            }
        }
        if (value.n_answers)
        {
            answers = new DnsAnswer[value.n_answers];

            DnsAnswer * from = other.GetAnswers();
            if (from)
            {
                for (auto i = 0; i < value.n_answers; i++)
                {
                    DnsAnswer & ref = (*from);
                    DnsAnswer * currentAnswer = &answers[i];

                    currentAnswer->cl_name = ref.cl_name;
                    currentAnswer->length = ref.length;
                    currentAnswer->offset = ref.offset;
                    currentAnswer->ttl = ref.ttl;
                    currentAnswer->type = ref.type;

                    if (ref.type == DNS_TYPE_A)
                    {
                        in_addr * dst_addr = &currentAnswer->adata.host_addr.address;
                        const in_addr * src_addr = &ref.adata.host_addr.address;
                        memcpy(dst_addr, src_addr, sizeof(in_addr));
                    }

                    else if (ref.type == DNS_TYPE_CNAME)
                    {
                        const uint8_t * name_ptr_src = ref.adata.cname.data;
                        const size_t name_size = DNS_DATA_LEN;

                        uint8_t * name_ptr_dst = &currentAnswer->adata.cname.data[0];

                        std::copy(name_ptr_src, name_ptr_src + name_size, name_ptr_dst);
                    }

                    const uint8_t * name_ptr = &ref.name[0];

                    const size_t name_size = DNS_DATA_LEN;

                    uint8_t * name_ptr_dst = &currentAnswer->name[0];
                    std::copy(name_ptr, name_ptr + name_size, name_ptr_dst);
                    from++;
                }
            }
        }

        return *this;
    }



    DNSHolder & operator=(const dnshdr& other)
    {
        value.id = other.id;
        value.flags = other.flags;
        value.n_questions = other.n_questions;
        value.n_answers = other.n_answers;
        value.n_authority = other.n_authority;
        value.n_addinfo = other.n_addinfo;
        questions = nullptr;
        answers = nullptr;
        CorrectData();
        return *this;
    }

    auto GetID() { return value.id; }
    auto GetFLAGS() { return value.flags; }
    auto GetNQ() { return value.n_questions; }
    auto GetNA() { return value.n_answers; }
    auto GetNAUTH() { return value.n_authority; }
    auto GetNADD() { return value.n_addinfo; }


    inline void AllocateQuestions()
    {
        questions = new DnsQuestion[value.n_questions];
    }
    inline void AllocateAnswers()
    {
        answers = new DnsAnswer[value.n_answers];
    }

    DnsQuestion * GetQuestions() const { return questions; }
    DnsAnswer * GetAnswers() const { return answers; }

    void SetMessageType(uint16_t qr)
    {
        this->qr = qr;
    }

    uint16_t GetMessageType(void) { return qr; }

    static void parseAllAnswers(DNSHolder * holder,const uint8_t * section_ptr, const uint8_t * dns_sec_ptr, size_t count)
    {
        int index = 0;
        holder->AllocateAnswers();
        DnsAnswer * answers = holder->GetAnswers();

        while (count)
        {
            size_t asize = ParseAnswer(section_ptr, dns_sec_ptr, &answers[index++]);
            section_ptr += asize;
            count--;
        }
    }

    static size_t parseAllQuestions(DNSHolder * holder, const uint8_t * dns_sec_ptr, uint16_t count)
    {
        int index = 0;
        holder->AllocateQuestions();
        DnsQuestion* arr = holder->GetQuestions();
        size_t parsed_size = ParseQuestion(count, dns_sec_ptr, &arr[index]);
        return parsed_size;
    }


    ~DNSHolder()
    {
        if (value.n_questions)
        {
            delete [] questions;
        }
        if (value.n_answers)
        {
            delete [] answers;
        }
    }

private:
    dnshdr value;            // dns header
    DnsQuestion * questions; // allocated if there is at least 1 query in dns message
    DnsAnswer   * answers;  // allocated if there is at least 1 answer in dns message
    void CorrectData()
    {
        value.id = ntohs(value.id);
        value.flags = ntohs(value.flags);
        value.n_questions = ntohs(value.n_questions);
        value.n_answers = ntohs(value.n_answers);
        value.n_authority = ntohs(value.n_authority);
        value.n_addinfo = ntohs(value.n_addinfo);
    }

    uint16_t qr;



};

class HTTPHolder
{

};


class ARPHolder
{
public:

    ARPHolder() = default;

    ARPHolder(const ARPHolder& other)
    {
        this->operator =(other.value);
    }


    ARPHolder & operator=(const ARPHolder& other)
    {
        value.h_len = other.value.h_len;
        value.h_type = other.value.h_type;
        value.operation = other.value.operation;
        value.p_len = other.value.p_len;
        value.p_type = other.value.p_type;

        for (auto i = 0; i < N_OCTETS; i++) value.sender_mac[i] = other.value.sender_mac[i];
        for (auto i = 0; i < N_OCTETS; i++) value.target_mac[i] = other.value.target_mac[i];


        for (auto i = 0; i < 4; i++) value.sender_laddr[i] = other.value.sender_laddr[i];
        for (auto i = 0; i < 4; i++) value.target_laddr[i] = other.value.target_laddr[i];

        const char * pretty_mac_sender_ptr = &other.mac_src[0];
        const char * pretty_mac_receiver_ptr = &other.mac_dst[0];

        std::copy(pretty_mac_sender_ptr, pretty_mac_sender_ptr + MAC_PRETTY_NAME, mac_src);
        std::copy(pretty_mac_receiver_ptr, pretty_mac_receiver_ptr + MAC_PRETTY_NAME, mac_dst);



        return *this;
    }


    ARPHolder &operator=(const Arp & other)
    {
        value.h_len = other.h_len;
        value.h_type = other.h_type;
        value.operation = other.operation;
        value.p_len = other.p_len;
        value.p_type = other.p_type;

        for (auto i = 0; i < N_OCTETS; i++) value.sender_mac[i] = other.sender_mac[i];
        for (auto i = 0; i < N_OCTETS; i++) value.target_mac[i] = other.target_mac[i];


        for (auto i = 0; i < 4; i++) value.sender_laddr[i] = other.sender_laddr[i];
        for (auto i = 0; i < 4; i++) value.target_laddr[i] = other.target_laddr[i];

        CorrectData();
        FormatAddresses();
        return *this;
    }

    auto ExtractSrcMac()
    {
        return mac_src;
    }

    auto ExtractDstMac()
    {
        return mac_dst;
    }

    auto ExtractOperation()
    {
        return value.operation;
    }

    inline auto getHType() { return value.h_type; }
    inline auto getPType() { return value.p_type; }
    inline auto getHSize() { return value.h_len; }
    inline auto getPSize() { return value.p_len; }


    const uint8_t * SourceIP() { return &value.sender_laddr[0]; }
    const uint8_t * DestIP() { return &value.target_laddr[0]; }

    void CorrectData()
    {
        value.operation = ntohs(value.operation);
        value.h_type = ntohs(value.h_type);
        value.p_type = ntohs(value.p_type);
    }

    void FormatAddresses()
    {
        sprintf_s(mac_src, MAC_PRETTY_NAME,MAC_FMT,
                  value.sender_mac[0],
                  value.sender_mac[1],
                  value.sender_mac[2],
                  value.sender_mac[3],
                  value.sender_mac[4],
                  value.sender_mac[5]);

        if (value.operation == 2)
        {
            sprintf_s(mac_dst, MAC_PRETTY_NAME,MAC_FMT,
                      value.target_mac[0],
                      value.target_mac[1],
                      value.target_mac[2],
                      value.target_mac[3],
                      value.target_mac[4],
                      value.target_mac[5]);
        }
        else
        {
            sprintf_s(mac_dst, MAC_PRETTY_NAME, "%s",MAC_UNKNOWN);
        }
    }

    ~ARPHolder() {}

private:
	Arp value;
    char mac_src[MAC_PRETTY_NAME];
    char mac_dst[MAC_PRETTY_NAME];
};







enum protocol_t
{
	CurrentIPv4,
	CurrentIPv6,
	CurrentARP,
	CurrentTCP,
	CurrentUDP,
	CurrentICMP,
	CurrentDNS,
    CurrentTLS,
    CurrentHTTP,
};

#define MAX_SUPPORT_PROTOS 7



struct ProtocolHolder
{
	protocol_t type;
    explicit ProtocolHolder() noexcept {}
    union
    {
		IPv4Holder	IP4_header;
		IPv6Holder	IP6_header;
		ARPHolder	arp_header;
		TCPHolder	tcp_header;
		UDPHolder	udp_header;
		ICMPHolder	icmp_header;
		DNSHolder	dns_header;
	};

	ProtocolHolder* next; // pointer to next node of protocol to read to

    ~ProtocolHolder()
    {
        switch (type)
        {
        case CurrentIPv4:   IP4_header.~IPv4Holder(); break;
        case CurrentIPv6:   IP6_header.~IPv6Holder(); break;
        case CurrentARP:    arp_header.~ARPHolder(); break;
        case CurrentTCP:    tcp_header.~TCPHolder(); break;
        case CurrentUDP:    udp_header.~UDPHolder(); break;
        case CurrentICMP:   icmp_header.~ICMPHolder(); break;
        case CurrentDNS:    dns_header.~DNSHolder(); break;
        }
    }

};



struct Packet
{
    Packet() : etherFrame{}
    {
        count = 0;
        head = nullptr;
        tail = nullptr;
        delta_time_calculated = 0.0;
        valid_ptr = false;
    }

    inline ProtocolHolder * First()
    {
        return head;
    }

    inline ProtocolHolder * Last()
    {
        return tail;
    }

    ether_header mHeader;
    time_t delta_time_calculated;
    size_t count;

    bool isValid()
    {
        return valid_ptr == true;
    }

    void setValid(bool valid) { valid_ptr = true; }

    void push_back(ProtocolHolder ** value)
    {
        if (head == nullptr)
        {
            head = (*value);
            tail = head;
            count = 1;
        }
        else
        {
            ProtocolHolder * cnode = head;

            while (cnode->next) cnode = cnode->next;

            cnode->next = (*value);
            tail = (*value);
            count++;
        }
    }



    Packet (Packet & other)
    {
        ProtocolHolder * tmp = other.head;
        head = nullptr;
        tail = nullptr;
        count = other.count;
        delta_time_calculated = other.delta_time_calculated;
        etherFrame = other.etherFrame;

        if (count > 0)
        {
            for (; tmp; tmp = tmp->next)
            {
                ProtocolHolder * value = new ProtocolHolder;
                value->next = nullptr;
                copyNode(&value, &tmp);
                push_back(&value);
            }
        }
    }

    ~Packet()
    {
        ProtocolHolder * current = head;
        while (current)
        {
            ProtocolHolder * toDeleteNode = current;
            current = current->next;
            delete toDeleteNode;
        }
    }

    void setEthernet(const Ethernet & value) {
        etherFrame = value;
    }

    const Ethernet & getEthernet() { return etherFrame; }

private:
    ProtocolHolder * head;
    ProtocolHolder * tail;
    Ethernet etherFrame;
    bool valid_ptr;
    void copyNode(ProtocolHolder ** dst, ProtocolHolder ** src)
    {
        ProtocolHolder * ref_from = (*src);
        ProtocolHolder * ref_to = (*dst);


        switch (ref_from->type)
        {
            case CurrentIPv4:
        {
            ref_to->IP4_header = ref_from->IP4_header;
            break;
        }
            case CurrentIPv6:
        {
            ref_to->IP6_header = ref_from->IP6_header;
            break;
        }
            case CurrentARP:
        {
            ref_to->arp_header = ref_from->arp_header;
            break;
        }
            case CurrentTCP:
        {

            ref_to->tcp_header = ref_from->tcp_header;
            break;
        }
            case CurrentUDP:
        {
            ref_to->udp_header = ref_from->udp_header;
            break;
        }
            case CurrentICMP:
        {
            ref_to->icmp_header = ref_from->icmp_header;
            break;
        }
            case CurrentDNS:
        {
            ref_to->dns_header = ref_from->dns_header;
            break;
        }
        }

        ref_to->type = ref_from->type;
    }
};


struct FrameInfo
{
    int f_num;              // frame number
    time_t recv_time;       // epoch time
    uint32_t total_length;  // total packet length
    uint32_t cap_len;       // wire length
    double alt_time;
    Packet * p_ref;         // packet
    QByteArray copy;
    FrameInfo()
    {
        p_ref = nullptr;
        f_num = 0;
        recv_time = 0;
        total_length = 0;
        cap_len = 0;
        alt_time = 0;
    }

    FrameInfo(const FrameInfo & frame)
    {
        f_num = frame.f_num;
        recv_time = frame.recv_time;
        total_length = frame.total_length;
        cap_len = frame.cap_len;
        alt_time = frame.alt_time;
        p_ref = new Packet(*frame.p_ref);
        copy = frame.copy;
    }

    ~FrameInfo()
    {
        delete p_ref;
    }


};
