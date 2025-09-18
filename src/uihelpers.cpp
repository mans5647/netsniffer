#include "uihelpers.h"
#include <algorithm>
#include <iomanip>
#include "protocolparser.h"

#define ADDR_V4     0
#define ADDR_V6     1
#define ARP_ADDR    2

QString getEthernetNextProtocolName(std::uint16_t Value)
{
    QString text;
    switch (Value)
    {
    case H_PROTO_IP4:
    {
        text = "Протокол IP, версии 4 ( IPv4 )";
        break;
    }
    case H_PROTO_IP6:
    {
        text = "Протокол IP, версии 6 ( IPv6 )";
        break;
    }
    case H_PROTO_ARP:
    {
        text = "Протокол определения адреса ( ARP )";
        break;
    }
    }
    return text;
}

QString getCurrentUTCTime()
{
    auto value =  QDateTime::currentDateTimeUtc();
    QString __fmt = value.toString(QString("MMMM d, yyyy hh:mm:ss:ms t"));
    return __fmt;
}

const QString & getLastProtocol(const ProtocolHolder * last)
{
    static QString out;
    out.clear();
    switch (last->GetType())
    {
    case CurrentIPv4:
    {
        out = "IPv4";
        break;
    }
    case CurrentIPv6:
    {
        out = "IPv6";
        break;
    }
    case CurrentICMP:
    {
        out = "ICMP";
        break;
    }
    case CurrentARP:
    {
        out = "ARP";
        break;
    }
    case CurrentTCP:
    {
        out = "TCP";
        break;
    }
    case CurrentUDP:
    {
        out = "UDP";
        break;
    }
    case CurrentDNS:
    {
        out = "DNS";
        break;
    }
    case CurrentHTTP:
    {
        out = "HTTP";
        break;
    }
    default:
    {
        out = "Unknown protocol";
        break;
    }
    }
    return out;
}



// const QString & getPacketInfo(ProtocolHolder * last)
// {
//     static QString message;
//     message.clear();

//     switch (last->GetType)
//     {
//     case CurrentTCP:
//     {
//         TCPHolder * ref = &last->tcp_header;
//         QString flags_set;


//         uint8_t flags = ref->ExtractFlags();

//         flags_set += "[";
//         if (flags & TH_SYN) flags_set += " SYN ";
//         if (flags & TH_ACK) flags_set += " ACK ";
//         if (flags & TH_FIN) flags_set += " FIN ";
//         if (flags & TH_PUSH) flags_set += " PUSH ";
//         if (flags & TH_RST) flags_set += " RST ";
//         if (flags & TH_URG) flags_set += " URG ";
//         flags_set += "]";

//         const char * status = ((flags & TH_SYN) && !(flags & TH_ACK)) ? "New connetion" :
//                                  (flags & TH_FIN) ? "Finished" : (flags & TH_RST) ? "Reset" : "Data exchange";
//         auto sport = ref->ExtractSPort();
//         auto dport = ref->ExtractDPort();
//         auto plen  = ref->GetPayloadLength();
//         QTextStream formatted(&message);
//         formatted << sport << " -> " << dport << ", flags: " << flags_set << " status: " << status;
//         break;
//     }
//     case CurrentUDP:
//     {

//         UDPHolder * ref = &last->udp_header;

//         auto sport = ref->ExtractSPort();
//         auto dport = ref->ExtractDPort();
//         auto plen  = ref->GetPayloadLength();

//         message = QString::asprintf("%d -> %d, len: %ld bytes", sport, dport, plen);
//         break;
//     }
//     case CurrentDNS:
//     {
//         DNSHolder * ref = &last->dns_header;

//         const char * opcode_message = "UNKNOWN";

//         auto id = ref->GetID();
//         auto flags = ref->GetFLAGS();
//         auto qcount = ref->GetNQ();
//         auto acount = ref->GetNA();
//         auto aa_cnt = ref->GetNAUTH();
//         auto ad_cnt = ref->GetNADD();
//         auto opcode = flags & DNS_FLAGS_OPCODE_MASK;

//         if (opcode == DNS_FLAGS_QUERY_STANDARD)
//             opcode_message = "STANDARD";
//         else if (opcode == DNS_FLAGS_QUERY_INVERSE)
//             opcode_message = "INVERSE";
//         else if (opcode == DNS_FLAGS_QUERY_STATUS)
//             opcode_message = "STATUS";

//         auto msg_type = flags & DNS_FLAGS_QR_MASK;

//         QTextStream fmt{&message};


//         auto rcode = flags & DNS_FLAGS_RCODE_MASK;

//         QString rcodeMessage;

//         switch (rcode)
//         {
//         case DNS_RCODE_NOERROR: rcodeMessage = "OK"; break;
//         case DNS_RCODE_NXDOMAIN: rcodeMessage = "No such name"; break;
//         case DNS_RCODE_FORMERR: rcodeMessage = "Format error"; break;
//         case DNS_RCODE_REFUSED: rcodeMessage = "Query Refused"; break;
//         case DNS_RCODE_SFAIL: rcodeMessage = "Server failure"; break;
//         case DNS_RCODE_NIMPL: rcodeMessage = "Not implemented"; break;
//         default: rcodeMessage = "Unknown message type"; break;
//         }

//         if (msg_type == DNS_FLAGS_QR_REPLY)
//         {

//             fmt << "DNS reply for domain ( ";
//             if (qcount)
//             {

//                 const DnsQuestion * ptr = ref->GetQuestions();

//                 for (auto i = 0; i < qcount; i++)
//                 {
//                     fmt << (*ptr).name;
//                     ptr++;
//                 }

//                 fmt << " )";
//             }


//             fmt << " [" << rcodeMessage << "] ";

//             fmt << " with id=0x" << QString("%1 ").arg(id, 0, 16, QChar('\0'));
//             if (acount)
//             {
//                 fmt << " has following answers: ";

//                 const DnsAnswer * ptr = ref->GetAnswers();

//                 for (auto i = 0; i < acount; i++)
//                 {
//                     const DnsAnswer & ref = (*ptr);
//                     QString answer_fmt;
//                     if (ref.type == DNS_TYPE_A)
//                     {
//                         char addrBuf[ADDR_V4_BUFLEN_MIN];

//                         FromIPv4Address(&addrBuf[0], ADDR_V4_BUFLEN_MIN, &ref.adata.host_addr.address);
//                         answer_fmt = QString("A (%1) ").arg(addrBuf);
//                     }

//                     else if (ref.type == DNS_TYPE_CNAME)
//                     {
//                         answer_fmt = QString("CNAME (%1) ").arg(reinterpret_cast<const char*>(ref.adata.cname.data));
//                     }

//                     fmt << answer_fmt;

//                     ptr++;
//                 }
//             }

//         }
//         else
//         {
//             fmt << "DNS request for domain ( ";
//             if (qcount)
//             {
//                 const DnsQuestion * ptr = ref->GetQuestions();
//                 for (auto i = 0; i < qcount; i++)
//                 {
//                     fmt << (*ptr).name;
//                     ptr++;
//                 }

//                 fmt << " )";
//             }

//             fmt << " with id=0x" << QString("%1 ").arg(id, 0, 16, QChar('\0'));
//         }
//         break;

//     }

//     case CurrentARP:
//     {
//         ARPHolder * ref = &last->arp_header;
//         auto type = ref->ExtractOperation();

//         QString __str;
//         QTextStream fmt(&__str);
//         if (type == 1)
//         {
//             const uint8_t * data = ref->DestIP();
//             const uint8_t * data_2 = ref->SourceIP();
//             fmt << "ARP request for address "<< (int)data[0] << '.' << (int)data[1] << '.' << (int)data[2] << '.' << (int)data[3]
//                 << " , tell MAC to " << (int)data_2[0] << '.' << (int)data_2[1] << '.' << (int)data_2[2] << '.' << (int)data_2[3] ;
//         }
//         else
//         {
//             const uint8_t * ip_ = ref->SourceIP();
//             const char * mac = ref->ExtractSrcMac();
//             fmt << "ARP response, " << (int)ip_[0] << '.' << (int)ip_[1] << '.' << (int)ip_[2] << '.' << (int)ip_[3]
//                 << " is " << mac;
//         }

//         message = __str;

//         break;
//     }

//     case CurrentICMP:
//     {
//         ICMPHolder * ref = &last->icmp_header;
//         auto icmp_msg_type = ref->getMessageType();
//         auto icmp_code = ref->getCode();
//         auto data_len = ref->getDataLength();
//         QString __str;
//         QTextStream fmt(&__str);
//         switch (icmp_msg_type)
//         {

//         case ICMPHolder::ICMPMessageType::Echo:
//         {
//             fmt << "Echo (request) ";
//             fmt << "id=0x" << QString("%1").arg(ref->getID());
//             fmt << " seq=" << (QString("%1").arg(ref->getSequenceNum()));
//             break;
//         }
//         case ICMPHolder::ICMPMessageType::EchoReply:
//         {
//             fmt << "Echo (reply) ";
//             fmt << "id=0x" << QString("%1").arg(ref->getID());
//             fmt << " seq=" << QString("%1").arg(ref->getSequenceNum());
//             break;
//             break;
//         }

//         }

//         fmt << " data length: " << QString("%1 bytes").arg(data_len);
//         message = __str;
//         break;
//     }

//     default:
//         break;
//     }

//     return message;
// }

QString getCurrentLocalTime()
{
    QDateTime local = QDateTime::currentDateTime();
    return local.toString("MMMM d, yyyy hh:mm:ss:ms");
}

// QString getFormattedProtocolNames(const FrameInfo * _value)
// {
//     const ProtocolHolder * __layer_node = _value->p_ref->First();
//     QString fmt;
//     while (__layer_node)
//     {
//         switch (__layer_node->type)
//         {
//         case CurrentIPv4:   fmt += "ip:";      break;
//         case CurrentIPv6:   fmt += "ipv6:";    break;
//         case CurrentARP:    fmt += "arp:";     break;
//         case CurrentTCP:    fmt += "tcp:";     break;
//         case CurrentUDP:    fmt += "udp:";        break;
//         case CurrentICMP:   fmt += "icmp:";    break;
//         case CurrentDNS:    fmt += "dns:"; break;
//         default: fmt += "."; break;
//         }

//         __layer_node = __layer_node->next;
//     }
//     return fmt;
// }

const QString getNameOfKey(Locale locale, const ValueOfLocale & value)
{
    QString _valueText;
    switch (locale)
    {
    case Locale::Ru: _valueText = getRussianLocaleParam(value); break;
    }

    return _valueText;
}

const QString getRussianLocaleParam(const ValueOfLocale & value)
{
    QString fmt;

    if (value.type == TypeOfValue::FrameProperty)
    {
        switch (value.value.overview_prop)
        {
        case PacketPropertyFrame::FrameN: fmt = "Номер пакета:"; break;
        case PacketPropertyFrame::FrameLen: fmt = "Длина (полная):"; break;
        case PacketPropertyFrame::FrameCapLen: fmt = "Длина (захваченный трафик):"; break;
        case PacketPropertyFrame::FrameUTCTime: fmt = "Время прибытия (UTC):"; break;
        case PacketPropertyFrame::FrameLocalTime: fmt = "Время прибытия (локальное время):"; break;
        case PacketPropertyFrame::FrameProtos: fmt = "Инкапсуляция:"; break;
        case PacketPropertyFrame::FrameEpochTime: fmt = "Абсолютное время прибытия (Unix-time):"; break;
        }
    }

    else if (value.type == TypeOfValue::IpProperty)
    {
        switch (value.value.ip_prop)
        {
                case PacketPropertyIp::Version: fmt = "Версия протокола:"; break;
                case PacketPropertyIp::Hlen: fmt = "Длина заголовка:"; break;
                case PacketPropertyIp::DSCP: fmt = "Сервисы:"; break;
                case PacketPropertyIp::ECN: fmt = "Флаг ECN:"; break;
                case PacketPropertyIp::Total: fmt = "Полная длина:"; break;
                case PacketPropertyIp::Id: fmt = "ID:"; break;
                case PacketPropertyIp::FlagsCommon: fmt = "Флаги:"; break;
                case PacketPropertyIp::Flag1: fmt = "Флаг 1 (зарезервировано)"; break;
                case PacketPropertyIp::Flag2: fmt = "Флаг 2 (не фрагментировать)"; break;
                case PacketPropertyIp::Flag3: fmt = "Флаг 3 (фрагментировать)"; break;
                case PacketPropertyIp::Offset: fmt = "Отступ:"; break;
                case PacketPropertyIp::Ttl: fmt = "Время жизни пакета:"; break;
                case PacketPropertyIp::Proto: fmt = "Следующий протокол:"; break;
                case PacketPropertyIp::Checksum: fmt = "Чек-сумма пакета"; break;
                case PacketPropertyIp::Src: fmt = "Отправитель:"; break;
                case PacketPropertyIp::Dst: fmt= "Получатель:"; break;
        }
    }

    return fmt;
}

QString getUTCFromTimeT(const time_t & _t)
{
    auto value = QDateTime::fromSecsSinceEpoch(_t, QTimeZone(QTimeZone::UTC));
    return value.toString("MMMM d, yyyy hh:mm:ss:ms t");
}

QString getLocalFromTimeT(const time_t & _t)
{
    auto value = QDateTime::fromSecsSinceEpoch(_t, QTimeZone(QTimeZone::LocalTime));
    return value.toString("MMMM d, yyyy hh:mm:ss:ms");
}




QString toHex(uint64_t value)
{
    return QString("0x%1").arg(QString::number(value, 16));
}

QString getIPNextProtocol(uint8_t value)
{
    QString out;

    switch (value)
    {
    case TCP_NEXT: out = "TCP (6)";     break;
    case UDP_NEXT: out = "UDP (17)";    break;
    case ICMP_NEXT: out = "ICMP (1)";   break;
    case IGMP_NEXT: out = "IGMP (2)";   break;
    }

    return out;
}

QString ipGetFlagsStr(bool first, bool second, bool third)
{
    QString __str;
    __str = __str + QString((first) ? "1" : "0");
    __str = __str + QString((second) ? "1" : "0");
    __str = __str + QString((third) ? "1" : "0");
    __str += ". ....";
    __str += " Flags: ";

    if (first) __str += "Reserved,";
    if (second) __str += "Don't fragment,";
    if (third) __str += "More fragment";
    return __str;
}

QString ipGetRStr(bool value)
{
    QString __str;

    if (value) __str += "1... .... set";
    else __str += "0... .... dont't set";
    return __str;
}

QString ipGetDFStr(bool value)
{
    QString __str;

    if (value) __str += ".1.. .... set";
    else __str += ".0.. .... dont't set";
    return __str;

}

QString ipGetMFStr(bool value)
{
    QString __str;

    if (value) __str += "..1. .... set";
    else __str += "..0. .... dont't set";
    return __str;
}

QString getARPHardwareType(int type)
{
    QString value;
    switch (type)
    {
    case 1: value = QString("%1 (%2)").arg("Ethernet").arg(type); break;
    }

    return value;
}

QString getARPProtocolType(int type)
{
    QString value;
    switch (type)
    {
    case H_PROTO_IP4: value = QString("%1 (%2)").arg("IPv4").arg(type); break;
    case H_PROTO_IP6: value = QString("%1 (%2)").arg("IPv6").arg(type); break;
    }

    return value;
}

QString getARPOpcodeType(int type)
{
    return (type == 1) ? QObject::tr("Запрос") : QObject::tr("Ответ");
}

const QString &getFormattedAddress(void * data, int addr_type)
{
    static QString ____v;
    return ____v;
}

QString DnsStrType(uint16_t __type)
{
    QString result;
    switch (__type)
    {
        case DNS_TYPE_A: result = "A (address)"; break;
        case DNS_TYPE_CNAME: result = "CNAME (canonical name)"; break;
        case DNS_TYPE_HTTPS: result = "HTTPS"; break;
        default: result = "unknown";
    }
    return result;
}

QString DnsStrClass(uint16_t __class)
{
    QString result;
    switch (__class)
    {
    case DNS_CLASS_IN: result = "Internet (IN)"; break;
    case DNS_CLASS_CH: result = "Chaos (CH)"; break;
    case DNS_CLASS_HS: result = "Hesiod (HS)"; break;
    case DNS_CLASS_CS: result = "Unassigned"; break;
    }

    return result;
}

QString DnsFmtFlag__query_type(uint16_t flags)
{
    auto msg_type = flags & DNS_FLAGS_QR_MASK;
    const char * msg = nullptr;
    if (msg_type == DNS_FLAGS_QR_REPLY)
    {
        msg = "1... .... .... .... = Ответ";
    }
    else msg = "0... .... .... .... = Запрос";

    return msg;
}

QString DnsFmtFlag__opcode(uint16_t flags)
{
    auto type = flags & DNS_FLAGS_OPCODE_MASK;
    const char * msg = nullptr;
    switch (type)
    {
    case DNS_FLAGS_QUERY_STANDARD: msg =    ".000 0... .... .... = Код операции: Стандартный запрос (0)"; break;
    case DNS_FLAGS_QUERY_INVERSE: msg =     ".... 1... .... .... = Код операции: Инверсивный запрос (2048)"; break;
    case DNS_FLAGS_QUERY_STATUS: msg =      "...1 .... .... .... = Код операции: Запрос о статусе (4096)"; break;
    }


    return msg;
}

QString DnsFmtFlags__is_auth(uint16_t flags)
{
    QString msg;
    if (flags & DNS_FLAGS_AA_SERVER)
    {
        msg = ".... .1.. .... .... = Ответственнен ли сервер: Сервер отвечает за этот домен";
    }
    else msg = ".... .0.. .... .... = Ответственнен ли сервер: Сервер не отвечает за этот домен";

    return msg;
}

QString DnsFmtFlags__is_trunc(uint16_t flags)
{
    QString msg;

    if (flags & DNS_FLAGS_TC)
    {
        msg = ".... ..1. .... .... = Сообщение обрезано: Сообщение обрезано";
    }

    else msg = ".... ..0. .... .... = Сообщение обрезано: Сообщение не обрезано";

    return msg;
}

QString DnsFmtFlags__is_rd(uint16_t flags)
{
    QString msg;

    if (flags & DNS_FLAGS_RD)
    {
        msg = ".... ...1 .... .... = Рекурсивный запрос: Сделать запрос рекурсивно";
    }
    else msg = ".... ...0 .... .... = Рекурсивный запрос: Не делать запрос рекурсивно";
    return msg;
}

QString DnsFmtFlags__z(uint16_t flags)
{
    return ".... .... .0.. .... = Z: зарезервировано (0)";
}

QString DnsFmtFlags__rcode(uint16_t flags)
{
    QString msg;
    auto rcode = flags & DNS_FLAGS_RCODE_MASK;

    switch (rcode)
    {
    case DNS_RCODE_NOERROR: msg =   ".... .... .... 0000 = Код ответа: Без ошибки (0)"; break;
    case DNS_RCODE_NXDOMAIN: msg =  ".... .... .... 0011 = Код ответа: Такого домена не существует (3)"; break;
    case DNS_RCODE_FORMERR: msg =   ".... .... .... 0001 = Код ответа: Ошибка форматирования (1)"; break;
    case DNS_RCODE_SFAIL: msg =     ".... .... .... 0010 = Код ответа: Ошибка сервера (2)"; break;
    case DNS_RCODE_NIMPL: msg =     ".... .... .... 0100 = Код ответа: Не реализовано (4)"; break;
    case DNS_RCODE_REFUSED: msg =   ".... .... .... 0101 = Код ответа: Отказано (5)"; break;
    }
    return msg;
}

QString DnsFmtFlags_is_ra(uint16_t flags)
{
    QString msg;

    if (flags & DNS_FLAGS_RA)
    {
        msg = ".... .... 1... .... = Доступна ли рекурсия: Да";
    }
    else msg = ".... .... 0... .... = Доспупна ли рекурсия: Нет";
    return msg;
}
