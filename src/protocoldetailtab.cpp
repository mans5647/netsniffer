#include "protocoldetailtab.h"
#include "dnsrecordssection.h"
#include "uihelpers.h"
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QFont>
#include <QScrollBar>

ParentArea::ParentArea(QWidget *parent) : QScrollArea(parent)
{
    setWidgetResizable(true);
    setBackgroundRole(QPalette::Base);
    setFrameShape(QFrame::NoFrame);
}

void ParentArea::SetChild(QWidget * widget)
{
    setWidget(widget);
}

ParentArea::~ParentArea()
{

}

void ParentArea::UpdateVerticalBar(int min, int max)
{

    verticalScrollBar()->setRange(min, max);
}

void ParentArea::UpdateHorizontalBar(int min, int max)
{
    horizontalScrollBar()->setRange(min, max);
}

BaseTabWidget::BaseTabWidget(ProtocolHolder * v_maybe,QWidget *parent) : QWidget(parent)
{
    layout = new QVBoxLayout();
    setLayout(layout);
    m_ptr = v_maybe;
    endSpace = new QSpacerItem(20, 400, QSizePolicy::Expanding, QSizePolicy::Minimum);
//    QFont font {"Havletica", 9};
//    font.setStyleHint(QFont::Monospace);
//    font.setBold(true);
//    setFont(font);
}

void BaseTabWidget::AddWidget(QWidget * widget)
{
    layout->addWidget(widget);
}

BaseTabWidget::~BaseTabWidget()
{
    delete layout;
}



EthernetDetailTab::EthernetDetailTab(const Ethernet * eth,QWidget *parent) : BaseTabWidget(nullptr,parent)
{
    src = new KeyValuePairWidget();
    dst = new KeyValuePairWidget();
    proto = new KeyValuePairWidget();
    srcValue = new QLabel();
    dstValue = new QLabel();
    protoValue = new QLabel();


    value = eth;
}

void EthernetDetailTab::commit()
{
    char buf_src[MAC_PRETTY_NAME], buf_dst[MAC_PRETTY_NAME];
    prettify_mac(buf_src, value->getSourceMac().data(), MAC_PRETTY_NAME);
    prettify_mac(buf_dst, value->getDestinationMac().data(), MAC_PRETTY_NAME);


    srcValue->setText(buf_src);
    dstValue->setText(buf_dst);

    auto protocol_ = value->getEtherType();
    protoValue->setText(getEthernetNextProtocolName(protocol_));

    src->Put("Физический адрес отправителя", srcValue);
    dst->Put("Физический адрес получателя", dstValue);
    proto->Put("Следующий протокол", protoValue);

    src->Commit();
    dst->Commit();
    proto->Commit();

    AddWidget(src);
    AddWidget(dst);
    AddWidget(proto);

    layout->addSpacerItem(endSpace);
}

EthernetDetailTab::~EthernetDetailTab()
{
    delete src;
    delete dst;
    delete proto;
}





GeneralInfoTab::GeneralInfoTab(const FrameInfo * frame,QWidget *parent) : BaseTabWidget(nullptr,parent)
{
    number = new KeyValuePairWidget();
    utc_arrival = new KeyValuePairWidget();
    local_arrival = new KeyValuePairWidget();
    epoch = new KeyValuePairWidget();
    len = new KeyValuePairWidget();
    captureLen = new KeyValuePairWidget();
    protocols = new KeyValuePairWidget();

    numberValue = new QLabel();
    utcValue = new QLabel();
    localValue = new QLabel();
    epoch_value = new QLabel();
    lenValue = new QLabel();
    captureLenValue = new QLabel();
    protocolsInFrameValue = new QLabel();

    this->frame = frame;

}

void GeneralInfoTab::commit()
{
    numberValue->setText(QString::number(frame->f_num));

    utcValue->setText(getUTCFromTimeT(frame->recv_time));
    localValue->setText(getLocalFromTimeT(frame->recv_time));

    epoch_value->setText(QString::number(frame->recv_time));
    lenValue->setText(QString("%1 bytes").arg(frame->total_length));

    captureLenValue->setText(QString("%1 bytes").arg(frame->cap_len));
    protocolsInFrameValue->setText(getFormattedProtocolNames(frame));


    ValueOfLocale locale_spec;
    locale_spec.type = TypeOfValue::FrameProperty;

    locale_spec.value.overview_prop = PacketPropertyFrame::FrameN;
    number->Put(getNameOfKey(Locale::Ru, locale_spec), numberValue);

    locale_spec.value.overview_prop = PacketPropertyFrame::FrameUTCTime;
    utc_arrival->Put(getNameOfKey(Locale::Ru, locale_spec), utcValue);

    locale_spec.value.overview_prop = PacketPropertyFrame::FrameLocalTime;
    local_arrival->Put(getNameOfKey(Locale::Ru, locale_spec), localValue);

    locale_spec.value.overview_prop = PacketPropertyFrame::FrameEpochTime;
    epoch->Put(getNameOfKey(Locale::Ru, locale_spec), epoch_value);

    locale_spec.value.overview_prop = PacketPropertyFrame::FrameLen;
    len->Put(getNameOfKey(Locale::Ru, locale_spec), lenValue);

    locale_spec.value.overview_prop = PacketPropertyFrame::FrameCapLen;
    captureLen->Put(getNameOfKey(Locale::Ru, locale_spec), captureLenValue);

    locale_spec.value.overview_prop = PacketPropertyFrame::FrameProtos;
    protocols->Put(getNameOfKey(Locale::Ru, locale_spec), protocolsInFrameValue);


    number->Commit();
    utc_arrival->Commit();
    local_arrival->Commit();
    epoch->Commit();
    len->Commit();
    captureLen->Commit();
    protocols->Commit();

    AddWidget(number);
    AddWidget(utc_arrival);
    AddWidget(local_arrival);
    AddWidget(epoch);
    AddWidget(len);
    AddWidget(captureLen);
    AddWidget(protocols);

    layout->addSpacerItem(endSpace);
}

GeneralInfoTab::~GeneralInfoTab()
{
    delete number,
    delete utc_arrival;
    delete local_arrival;
    delete epoch;
    delete len;
    delete captureLen;
    delete protocols;
}


V4_Tab::V4_Tab(ProtocolHolder * value) : BaseTabWidget(nullptr)
{
    this->value = value;
    version_field = new kp;
    header_len_field = new kp;
    dscp_field = new kp;
    ecn_field = new kp;
    total_length_field = new kp;
    id_field = new kp;
    flags_common_field = new kp;
    flags_reserved = new kp;
    flags_dont_fragment = new kp;
    flags_more_fragments = new kp;
    fragment_offset_field = new kp;
    ttl_field = new kp;
    protocol_field = new kp;
    checksum_field = new kp;
    source_field = new kp;
    destination_field = new kp;
}

void V4_Tab::commit()
{
    QLabel * version = new QLabel;
    QLabel * hlen = new QLabel;
    QLabel * dscp = new QLabel;
    QLabel * ecn = new QLabel;
    QLabel * tlen = new QLabel;
    QLabel * id = new QLabel;
    QLabel * fl_common = new QLabel;
    QLabel * fl_rsv = new QLabel;
    QLabel * fl_df = new QLabel;
    QLabel * fl_mf = new QLabel;
    QLabel * offset = new QLabel;
    QLabel * ttl = new QLabel;
    QLabel * proto = new QLabel;
    QLabel * chsum = new QLabel;
    QLabel * source = new QLabel;
    QLabel * destination = new QLabel;

    IPv4Holder * v4_header = &value->IP4_header;
    version->setText(QString::number(v4_header->ExtractVersion()));
    hlen->setText(QString("%1 bytes").arg(v4_header->ExtractIHL()));
    dscp->setText("");
    ecn->setText("");

    tlen->setText(QString("%1 bytes").arg(v4_header->ExtractTotalLength()));
    id->setText(QString("%1").arg(v4_header->ExtractIdentity(), 0, 16, QChar('0')));


    auto flags = v4_header->ExtractFFlags();

    auto first = std::get<0>(flags);
    auto second = std::get<1>(flags);
    auto third = std::get<2>(flags);

    auto flags_str = ipGetFlagsStr(first, second, third);


    fl_common->setText(flags_str);

    fl_rsv->setText(ipGetRStr(first));
    fl_df->setText(ipGetDFStr(second));
    fl_mf->setText(ipGetMFStr(third));


    offset->setText(QString("%1 bytes").arg(v4_header->ExtractFragmentOffset()));
    ttl->setText(QString("%1 times").arg(v4_header->ExtractTTL()));
    proto->setText(getIPNextProtocol(v4_header->ExtractNextProto()));

    chsum->setText(QString("0x%1").arg(v4_header->ExtractChecksum()));
    source->setText(v4_header->ExtractSrcAddr());
    destination->setText(v4_header->ExtractDstAddr());


    version_field->Put(tr("Версия:"), version);
    header_len_field->Put(tr("Длина заголовка:"), hlen);
    dscp_field->Put(tr("DSCP поля:"), dscp);
    ecn_field->Put(tr("ECN поля:"), ecn);
    total_length_field->Put(tr("Полная длина:"), tlen);
    id_field->Put(tr("ID сессии:"), id);
    flags_common_field->Put(tr("Флаги:"), fl_common);

    flags_reserved->Put(tr("Резервировать?"), fl_rsv);
    flags_dont_fragment->Put(tr("Фрагментировать?"), fl_df);
    flags_more_fragments->Put(tr("Еще фрагменты?"), fl_mf);

    fragment_offset_field->Put(tr("Смещение фрагмента:"), offset);
    ttl_field->Put(tr("Время жизни:"), ttl);
    protocol_field->Put(tr("Протокол верхнего уровня:"), proto);
    checksum_field->Put(tr("Контрольная сумма:"), chsum);
    source_field->Put(tr("Отправитель:"), source);
    destination_field->Put(tr("Получатель:"), destination);



    version_field->Commit();
    header_len_field->Commit();
    dscp_field->Commit();
    ecn_field->Commit();
    total_length_field->Commit();
    id_field->Commit();
    flags_common_field->Commit();

    flags_reserved->Commit();
    flags_dont_fragment->Commit();
    flags_more_fragments->Commit();

    fragment_offset_field->Commit();
    ttl_field->Commit();
    protocol_field->Commit();
    checksum_field->Commit();
    source_field->Commit();
    destination_field->Commit();


    AddWidget(version_field);
    AddWidget(header_len_field);
    AddWidget(total_length_field);
    AddWidget(dscp_field);
    AddWidget(ecn_field);
    AddWidget(id_field);
    AddWidget(flags_common_field);
    AddWidget(flags_reserved);
    AddWidget(flags_dont_fragment);
    AddWidget(flags_more_fragments);

    AddWidget(fragment_offset_field);
    AddWidget(ttl_field);
    AddWidget(protocol_field);
    AddWidget(checksum_field);
    AddWidget(source_field);
    AddWidget(destination_field);
}

V4_Tab::~V4_Tab()
{
    delete version_field;
    delete header_len_field;
    delete dscp_field;
    delete ecn_field;
    delete total_length_field;
    delete id_field;
    delete flags_common_field;
    delete flags_reserved;
    delete flags_dont_fragment;
    delete flags_more_fragments;
    delete fragment_offset_field;
    delete ttl_field;
    delete protocol_field;
    delete checksum_field;
    delete source_field;
    delete destination_field;
}




GenericTab::GenericTab(TabType type, const FrameInfo * frame, ProtocolHolder * value_maybe)
{
    mainWidget = new ParentArea();

    this->type = type;

    switch (type)
    {
    case TabType::General:
    {
        internal.pinfo = new GeneralInfoTab(frame);
        mainWidget->SetChild(internal.pinfo);
        break;
    }
    case TabType::Ethernet:
    {
        const Ethernet & _eth = frame->p_ref->getEthernet();
        internal.eth = new EthernetDetailTab(&_eth);
        mainWidget->SetChild(internal.eth);
        break;
    }
    case TabType::V4:
    {
        internal.v4 = new V4_Tab(value_maybe);
        mainWidget->SetChild(internal.v4);
        break;
    }
    case TabType::ARP:
    {
        internal._arp = new ArpTab(value_maybe);
        mainWidget->SetChild(internal._arp);
        break;
    }

    case TabType::TCP:
    {
        internal._tcp = new TCPTab(value_maybe);
        mainWidget->SetChild(internal._tcp);
        break;
    }
    case TabType::UDP:
    {
        internal._udp = new UDPTab(value_maybe);
        mainWidget->SetChild(internal._udp);
        break;
    }

    case TabType::ICMP:
    {
        internal._icmp = new ICMPTab(value_maybe);
        mainWidget->SetChild(internal._icmp);
        break;
    }
    case TabType::DNS:
    {
        internal._dns = new DnsTab(value_maybe);
        mainWidget->SetChild(internal._dns);
        connect(internal._dns, &DnsTab::sectionSizeChanged, mainWidget, &ParentArea::UpdateVerticalBar);
        break;
    }

    default:
        break;
    }
}










GenericTab::GenericTab(GenericTab && other) noexcept
{
    mainWidget = other.mainWidget;
    switch (other.type)
    {
    case TabType::General:
    {
        internal.pinfo = other.internal.pinfo;
        mainWidget->SetChild(internal.pinfo);
        break;
    }
    case TabType::Ethernet:
    {
        internal.eth = other.internal.eth;
        mainWidget->SetChild(internal.eth);
        break;
    }
    }

    type = other.type;
}






ParentArea *GenericTab::getMainWidget()
{
    return mainWidget;
}

tab* GenericTab::getTab()
{
    return &internal;
}

TabType GenericTab::getType()
{
    return type;
}

GenericTab::~GenericTab()
{
    switch (type)
    {
        case TabType::General: delete internal.pinfo;   break;
        case TabType::Ethernet: delete internal.eth;    break;
        case TabType::V4: delete internal.v4;           break;
        case TabType::ARP: delete internal._arp;        break;
        case TabType::TCP: delete internal._tcp;        break;
        case TabType::UDP: delete internal._udp;        break;
        case TabType::ICMP: delete internal._icmp;      break;
        case TabType::DNS: delete internal._dns;        break;
    }

    delete mainWidget;
}



ArpTab::ArpTab(ProtocolHolder * value) : BaseTabWidget(nullptr)
{
    this->value = value;

    htype_field =       new kp;
    ptype_field =       new kp;
    hsize =             new kp;
    psize =             new kp;
    opcode_field =      new kp;
    macsender_field =   new kp;
    ipsender_field =    new kp;
    macrecv_field =     new kp;
    iprecv_field =      new kp;

    htypevalue =            new QLabel;
    ptypevalue =            new QLabel;
    hszvalue =              new QLabel;
    pszvalue =              new QLabel;
    opcode_value =          new QLabel;
    media_value_sender =    new QLabel;
    address_value_sender =    new QLabel;
    media_value_recv =    new QLabel;
    address_value_recv =  new QLabel;

}

void ArpTab::commit()
{
    ARPHolder * a_ptr = &value->arp_header;
    htypevalue->setText(getARPHardwareType(a_ptr->getHType()));
    ptypevalue->setText(getARPProtocolType(a_ptr->getPType()));
    hszvalue->setText(QString("%1 bytes").arg(a_ptr->getHSize()));
    pszvalue->setText(QString("%1 bytes").arg(a_ptr->getPSize()));
    opcode_value->setText(getARPOpcodeType(a_ptr->ExtractOperation()));
    media_value_sender->setText(a_ptr->ExtractSrcMac());
    auto source_ip = a_ptr->SourceIP();
    auto dest_ip = a_ptr->DestIP();
    address_value_sender->setText(QString("%1.%2.%3.%4").arg(source_ip[0]).arg(source_ip[1]).arg(source_ip[2]).arg(source_ip[3]));

    media_value_recv->setText(a_ptr->ExtractDstMac());

    address_value_recv->setText(QString("%1.%2.%3.%4").arg(dest_ip[0]).arg(dest_ip[1]).arg(dest_ip[2]).arg(dest_ip[3]));

    htype_field->Put(tr("Тип канального протокола:"), htypevalue);
    ptype_field->Put(tr("Тип сетевого протокола:"), ptypevalue);
    hsize->Put(tr("Размер (канальный протокол):"), hszvalue);
    psize->Put(tr("Размер (сетевой протокол):"), pszvalue);

    opcode_field->Put(tr("Тип операции:"), opcode_value);
    macsender_field->Put(tr("Физический адрес отправителя:"), media_value_sender);
    macrecv_field->Put(tr("Физический адрес получателя:"), media_value_recv);

    ipsender_field->Put(tr("Логический адрес отправителя:"), address_value_sender);
    iprecv_field->Put(tr("Логический адрес получателя:"), address_value_recv);


    htype_field->Commit();
    ptype_field->Commit();
    hsize->Commit();
    psize->Commit();
    opcode_field->Commit();
    macsender_field->Commit();
    ipsender_field->Commit();
    macrecv_field->Commit();
    iprecv_field->Commit();

    AddWidget(htype_field);
    AddWidget(ptype_field);
    AddWidget(hsize);
    AddWidget(psize);
    AddWidget(opcode_field);
    AddWidget(macsender_field);
    AddWidget(ipsender_field);
    AddWidget(macrecv_field);
    AddWidget(iprecv_field);
}

ArpTab::~ArpTab()
{
    delete htype_field;
    delete ptype_field;
    delete hsize;
    delete psize;
    delete opcode_field;
    delete macsender_field;
    delete ipsender_field;
    delete macrecv_field;
    delete iprecv_field;
}

TCPTab::TCPTab(ProtocolHolder * value) : BaseTabWidget(value)
{
    src_field = new kp;
    dst_field = new kp;
    seq_field = new kp;
    ack_field = new kp;
    hlen_field = new kp;
    flags_formatted_field = new kp;

    for (auto i = 0; i < std::size(flags_pair_fields); i++) flags_pair_fields[i] = new kp;

    wnd_size_field = new kp;
    checksum_ptr_field = new kp;
    urgent_field = new kp;

}

TCPTab::~TCPTab()
{
    delete src_field;
    delete dst_field;
    delete seq_field;
    delete ack_field;
    delete hlen_field;
    delete flags_formatted_field;


    for (auto i = 0; i < std::size(flags_pair_fields); i++) delete flags_pair_fields[i];

    delete wnd_size_field;
    delete checksum_ptr_field;
    delete urgent_field;
}


void TCPTab::commit()
{

    src_value =             new QLabel;
    dst_value =             new QLabel;
    seq_value =             new QLabel;
    ack_value =             new QLabel;
    hlen_value =            new QLabel;
    flags_formatted_value = new QLabel;
    wnd_size_value =        new QLabel;
    chk_sum_value =         new QLabel;
    urgent_value =          new QLabel;
    for (auto i = 0; i < std::size(flags_pair_values); i++) flags_pair_values[i] = new QLabel;


    TCPHolder * t_ptr = &m_ptr->tcp_header;

    src_value->setText(QString::number(t_ptr->ExtractSPort()));
    dst_value->setText(QString::number(t_ptr->ExtractDPort()));

    seq_value->setText(QString::number(t_ptr->ExtractSeqNum()));
    ack_value->setText(QString::number(t_ptr->ExtractAckNum()));

    hlen_value->setText(QString("(%1 * 4) = %2 bytes").arg(t_ptr->ExtractRawHeaderSize()).arg(t_ptr->ExtractHeaderSize()));

    wnd_size_value->setText(QString("%1").arg(t_ptr->ExtractWindSize()));
    urgent_value->setText(QString("%1").arg(t_ptr->ExtractUrgentPtr()));
    auto flags = t_ptr->ExtractFlags();

    QString ffmt;
    auto ld_flags = [&](uint8_t flags) {

        ffmt = "( ";

        if (flags & TH_FIN)     ffmt += "FIN,";
        if (flags & TH_SYN)     ffmt += "SYN,";
        if (flags & TH_RST)     ffmt += "RST,";
        if (flags & TH_PUSH)    ffmt += "PUSH,";
        if (flags & TH_ACK)     ffmt += "ACK,";
        if (flags & TH_URG)     ffmt += "URG,";
        if (flags & TH_ECE)     ffmt += "ECE";
        if (flags & TH_CWR)     ffmt += "CWR";

        ffmt += " )";

    };


    flags_formatted_value->setText(ffmt);

    auto ld_flags_each = [&](uint8_t flags, int what) -> QString {

        QString local;
        switch (what)
        {
        case 0:
        {
            local = (flags & TH_FIN) ? ".... ...1" : ".... ...0";
            break;
        }
        case 1:
        {
            local = (flags & TH_SYN) ? ".... ..1." : ".... ..0.";
            break;
        }
        case 2:
        {
            local = (flags & TH_RST) ? ".... .1.." : ".... .0..";
            break;
        }
        case 3:
        {
            local = (flags & TH_PUSH) ? ".... 1..." : ".... 0...";
            break;
        }
        case 4:
        {
            local = (flags & TH_ACK) ? "...1 ...." : "...0 ....";
            break;
        }
        case 5:
        {
            local = (flags & TH_URG) ? "..1. ...." : "..0. ....";
            break;
        }
        case 6:
        {
            local = (flags & TH_ECE) ? ".1.. ...." : ".0.. ....";
            break;
        }
        case 7:
        {
            local = (flags & TH_CWR) ? "1... ...." : "0... ....";
            break;
        }
        }

        return local;

    };

    ld_flags(flags);
    flags_formatted_value->setText(ffmt);

    flags_pair_values[0]->setText(ld_flags_each(flags, 0));
    flags_pair_values[1]->setText(ld_flags_each(flags, 1));
    flags_pair_values[2]->setText(ld_flags_each(flags, 2));
    flags_pair_values[3]->setText(ld_flags_each(flags, 3));
    flags_pair_values[4]->setText(ld_flags_each(flags, 4));
    flags_pair_values[5]->setText(ld_flags_each(flags, 5));
    flags_pair_values[6]->setText(ld_flags_each(flags, 6));
    flags_pair_values[7]->setText(ld_flags_each(flags, 7));

    src_field->Put(tr("Порт отправителя:"), src_value);
    dst_field->Put(tr("Порт получателя:"), dst_value);
    seq_field->Put(tr("Номер последовательности:"), seq_value);
    ack_field->Put(tr("Номер подтверждения:"), ack_value);
    hlen_field->Put(tr("Длина заголовка:"), hlen_value);

    flags_formatted_field->Put(tr("Флаги:"), flags_formatted_value);
    flags_pair_fields[0]->Put(tr("Флаг FIN  (Завершить):"), flags_pair_values[0]);
    flags_pair_fields[1]->Put(tr("Флаг SYN  (Установка соедениния):"), flags_pair_values[1]);
    flags_pair_fields[2]->Put(tr("Флаг RST  (Сбросить):"), flags_pair_values[2]);
    flags_pair_fields[3]->Put(tr("Флаг PUSH (Немедленно отправить):"), flags_pair_values[3]);
    flags_pair_fields[4]->Put(tr("Флаг ACK  (Номер подтверждения):"), flags_pair_values[4]);
    flags_pair_fields[5]->Put(tr("Флаг URG  (Важность):"), flags_pair_values[5]);
    flags_pair_fields[6]->Put(tr("Флаг ECN-Echo (Уменьшить скорость передачи):"), flags_pair_values[6]);
    flags_pair_fields[7]->Put(tr("Флаг CWR (Скорость уменьшена):"), flags_pair_values[7]);


    wnd_size_field->Put(tr("Размер окна:"), wnd_size_value);
    urgent_field->Put(tr("Указатель важности:"), urgent_value);


    src_field->Commit();
    dst_field->Commit();
    seq_field->Commit();
    ack_field->Commit();
    hlen_field->Commit();
    flags_formatted_field->Commit();

    for (auto i = 0; i < std::size(flags_pair_fields); i++) flags_pair_fields[i]->Commit();

    wnd_size_field->Commit();
    urgent_field->Commit();

    AddWidget(src_field);
    AddWidget(dst_field);
    AddWidget(seq_field);
    AddWidget(ack_field);
    AddWidget(hlen_field);
    AddWidget(flags_formatted_field);

    for (auto i = 0; i < std::size(flags_pair_fields); i++) AddWidget(flags_pair_fields[i]);


    AddWidget(wnd_size_field);
    AddWidget(urgent_field);
}


UDPTab::UDPTab(ProtocolHolder * _value) : BaseTabWidget(_value)
{
    SourcePort_field = new kp;
    DestinationPort_field = new kp;
    Length_field = new kp;
    Checksum_field = new kp;

    SourcePort_value = new QLabel;
    DestinationPort_value = new QLabel;
    Length_value = new QLabel;
    Checksum_value = new QLabel;

}

void UDPTab::commit()
{
    UDPHolder * _udp = &m_ptr->udp_header;

    SourcePort_value->setText(QString("%1").arg(_udp->ExtractSPort()));
    DestinationPort_value->setText(QString("%1").arg(_udp->ExtractDPort()));
    Length_value->setText(QString("%1 байт").arg(_udp->ExtractLen()));
    Checksum_value->setText(QString("0x%1").arg(_udp->ExtractSum(), 0, 16, QChar('\0')));


    SourcePort_field->Put(tr("Порт отправителя:"), SourcePort_value);
    DestinationPort_field->Put(tr("Порт получателя:"), DestinationPort_value);
    Length_field->Put(tr("Длина полезной нагрузки:"), Length_value);
    Checksum_field->Put(tr("Контрольная сумма:"), Checksum_value);

    SourcePort_field->Commit();
    DestinationPort_field->Commit();
    Length_field->Commit();
    Checksum_field->Commit();

    AddWidget(SourcePort_field);
    AddWidget(DestinationPort_field);
    AddWidget(Length_field);
    AddWidget(Checksum_field);

    layout->addSpacerItem(endSpace);
}

UDPTab::~UDPTab()
{
    delete SourcePort_field;
    delete DestinationPort_field;
    delete Length_field;
    delete Checksum_field;
}

ICMPTab::ICMPTab(ProtocolHolder * value) : BaseTabWidget(value)
{
    TypeField = new kp;
    CodeField = new kp;
    ChecksumField = new kp;

    tree = new QTreeWidget();
    tree->setFrameShape(QFrame::NoFrame);
    expander = new QTreeWidgetItem();

    expander->setText(0, "Данные");

    tree->addTopLevelItem(expander);
    tree->setHeaderHidden(true);
    tree->setMinimumSize(QSize( width() / 2, height() / 2 ));

    data_ip_header_child = nullptr;
    data_raw_child = nullptr;
}

void ICMPTab::commit()
{
    QLabel * typeValue = new QLabel{};
    QLabel * codeValue = new QLabel{};
    QLabel * checksumValue = new QLabel{};

    ICMPHolder * ptr = &m_ptr->icmp_header;


    int itype = 0;
    int icode = 0;


    ICMPHolder::ICMPMessageType etype = ptr->getMessageType();
    ICMPHolder::code_t ecode = ptr->getCode();

    itype = static_cast<int>(etype);


    QString typeExplanation;
    QString codeExplanation;


    QString id_replacement;

    switch (etype)
    {
    case ICMPHolder::ICMPMessageType::Echo:
    {
        typeExplanation = tr("Echo (запрос)");
        codeExplanation = "OK";


        icode = static_cast<int>(std::get<ICMPHolder::ICMP_EchoReplyCode>(ecode));

        break;
    }
    case ICMPHolder::ICMPMessageType::EchoReply:
    {
        typeExplanation = tr("Echo (ответ)");
        codeExplanation = "OK";
        break;
    }
    case ICMPHolder::ICMPMessageType::DestinationUnreachable:
    {
        typeExplanation = tr("Получатель недоступен");
        id_replacement = "unused";

        ICMPHolder::ICMP_DuCode dcode = std::get<ICMPHolder::ICMP_DuCode>(ecode);
        icode = static_cast<int>(dcode);
        switch (dcode)
        {
        case ICMPHolder::ICMP_DuCode::NetU: codeExplanation = tr("Сеть недоступна"); break;
        case ICMPHolder::ICMP_DuCode::HostU: codeExplanation = tr("Хост недоступен"); break;
        case ICMPHolder::ICMP_DuCode::ProtoU:codeExplanation = tr("Протокол недоступен"); break;
        case ICMPHolder::ICMP_DuCode::PortU:codeExplanation = tr("Порт недоступен"); break;
        case ICMPHolder::ICMP_DuCode::FNeeded:codeExplanation = tr("Фрагментация включена, но флаг DF есть"); break;
        case ICMPHolder::ICMP_DuCode::SRCRouteFailed:codeExplanation = tr("Путь недоступен"); break;
        }

        break;
    }

    case ICMPHolder::ICMPMessageType::SourceQuench:
    {
        typeExplanation = tr("Подавление источника");
        codeExplanation = tr("OK");
        break;
    }

    case ICMPHolder::ICMPMessageType::ParamProblem:
    {
        typeExplanation = tr("Проблема заголовков");
        codeExplanation = tr("См. указатель");
        break;
    }

    case ICMPHolder::ICMPMessageType::Redirect:
    {
        typeExplanation = tr("Перенаправление");
        id_replacement = "Address";

        ICMPHolder::ICMP_RedirectCode rcode = std::get<ICMPHolder::ICMP_RedirectCode>(ecode);

        icode = static_cast<int>(rcode);

        switch (rcode)
        {
        case ICMPHolder::ICMP_RedirectCode::RedirToNet: codeExplanation = tr("Перенаправлять к сети"); break;
        case ICMPHolder::ICMP_RedirectCode::RedirToHost: codeExplanation = tr("Перенаправлять к хосту"); break;
        case ICMPHolder::ICMP_RedirectCode::RedirToTosNet: codeExplanation = tr("Перенапрвлять к TOS сети"); break;
        case ICMPHolder::ICMP_RedirectCode::RedirToTosHost: codeExplanation = tr("Перенапрвлять к TOS хоста"); break;
        }

        break;
    }
    case ICMPHolder::ICMPMessageType::InfoReply:
    {
        typeExplanation = tr("Инфо (ответ)");
        break;
    }
    case ICMPHolder::ICMPMessageType::InfoRequest:
    {
        typeExplanation = tr("Инфо (запрос)");
        break;
    }
    case ICMPHolder::ICMPMessageType::TimeExceeded:
    {
        typeExplanation = tr("Время вышло");

        auto tcode = std::get<ICMPHolder::ICMP_TimeExCode>(ecode);

        if (tcode == ICMPHolder::ICMP_TimeExCode::TtlExceeded)
        {
            codeExplanation = tr("Время жизни пакета исчерпано");
        }
        else codeExplanation = tr("Время пересборки пакета исчерпано");

        break;
    }
    case ICMPHolder::ICMPMessageType::Timestamp:
    {
        typeExplanation = tr("Временная метка (запрос)");
        break;
    }
    case ICMPHolder::ICMPMessageType::TimestampReply:
    {
        typeExplanation = tr("Временная метка (ответ)");
        break;
    }
    default:
        typeExplanation = tr("Not recognized code 'cause not impl");
    }



    typeValue->setText(QString("%1 %2").arg(itype).arg(typeExplanation));
    codeValue->setText(QString("%1 %2").arg(icode).arg(codeExplanation));
    checksumValue->setText(QString("0x%1").arg(ptr->getChecksum(), 0, 16, QChar('\0')));




    auto icmp_data = ptr->getData();

    auto index = icmp_data.index();

    if (index == 0)
    {

    }

    else if (index == 1)
    {

        const std::string & rawDataRef = std::get<std::string>(icmp_data);
        kp_ptr RawDataField = new kp;

        QString ui_string = QString::fromStdString(rawDataRef);
        QLabel * display_dev = new QLabel(ui_string);
        RawDataField->Put(tr("Data:"), display_dev);
        RawDataField->Commit();

        data_raw_child = new QTreeWidgetItem{};

        expander->addChild(data_raw_child);
        tree->setItemWidget(data_raw_child, 0, RawDataField);
    }


    TypeField->Put(tr("Тип:"), typeValue);
    CodeField->Put(tr("Код:"), codeValue);
    ChecksumField->Put(tr("Чек-сумма:"), checksumValue);

    TypeField->Commit();
    CodeField->Commit();
    ChecksumField->Commit();


    AddWidget(TypeField);
    AddWidget(CodeField);
    AddWidget(ChecksumField);


    AddWidget(tree);
}

ICMPTab::~ICMPTab()
{

}



DnsTab::DnsTab(ProtocolHolder * value) : BaseTabWidget(value)
{
    tree = new QTreeWidget;
    tree->setHeaderHidden(true);
    tree->setFrameShape(QFrame::NoFrame);
    flagsTree = new QTreeWidget;
    flagsTree->setHeaderHidden(true);
    flagsTree->setFrameShape(QFrame::NoFrame);



    TransactionIdField = new kp;
    QCountField = new kp;
    ARRField = nullptr;
    AuthRRField = nullptr;
    AddRRField = nullptr;

    DNSHolder * ptr = &m_ptr->dns_header;
    asection = new QTreeWidgetItem;
    qsection = new QTreeWidgetItem;

    qsection->setText(0, tr("Запросы (%1)").arg(ptr->GetNQ()));
    asection->setText(0, tr("Ответы (%1)").arg(ptr->GetNA()));
}

void DnsTab::commit()
{
    DNSHolder * ptr = &m_ptr->dns_header;

    auto qcount = ptr->GetNQ();
    auto acount = ptr->GetNA();
    auto authCount = ptr->GetNAUTH();
    auto addCount = ptr->GetNADD();
    auto id = ptr->GetID();

    auto flags = ptr->GetFLAGS();

    QLabel * idValue =      new QLabel(QString("0x%1").arg(id, 0, 16, QChar('\0')));
    QLabel * qValue =       new QLabel(QString("%1").arg(qcount));

    QTreeWidgetItem * flagsExpander = new QTreeWidgetItem(flagsTree);

    flagsExpander->setText(0, tr("Флаги"));

    auto msg_type = flags & DNS_FLAGS_QR_MASK;

    auto qr_child = new QTreeWidgetItem(flagsExpander);
    auto opcode_child = new QTreeWidgetItem(flagsExpander);
    auto is_tr = new QTreeWidgetItem;
    auto is_rd = new QTreeWidgetItem;
    auto z_child = new QTreeWidgetItem;
    qr_child->setText(0, DnsFmtFlag__query_type(flags));
    opcode_child->setText(0, DnsFmtFlag__opcode(flags));
    is_tr->setText(0, DnsFmtFlags__is_trunc(flags));
    is_rd->setText(0, DnsFmtFlags__is_rd(flags));
    z_child->setText(0, DnsFmtFlags__z(flags));

    if (msg_type == DNS_FLAGS_QR_REPLY)
    {
        auto is_auth_child = new QTreeWidgetItem(flagsExpander);

        flagsExpander->addChild(is_tr);
        flagsExpander->addChild(is_rd);

        auto is_ra_child = new QTreeWidgetItem(flagsExpander);
        is_auth_child->setText(0, DnsFmtFlags__is_auth(flags));
        is_ra_child->setText(0, DnsFmtFlags_is_ra(flags));
        flagsExpander->addChild(z_child);
        auto rcode_child = new QTreeWidgetItem(flagsExpander);
        rcode_child->setText(0, DnsFmtFlags__rcode(flags));
    }
    else
    {
        flagsExpander->addChild(is_tr);
        flagsExpander->addChild(is_rd);
        flagsExpander->addChild(z_child);
    }



    DnsQuestion * qst = ptr->GetQuestions();

    if (qcount)
    {

        for (auto i = 0; i < qcount; i++)
        {
            QString name = qst[i].name;
            QString typeName = DnsStrType(qst[i].type);
            QString className = DnsStrClass(qst[i].cl_name);

            QTreeWidgetItem * entry = new QTreeWidgetItem;

            entry->setText(0, QString("%1 тип %2 класс %3").arg(name).arg(typeName).arg(className));
            QTreeWidgetItem * entry_name = new QTreeWidgetItem(entry);
            QTreeWidgetItem * entry_type = new QTreeWidgetItem(entry);
            QTreeWidgetItem * entry_class = new QTreeWidgetItem(entry);
            entry_name->setText(0, QString("Имя домена: %1").arg(name));
            entry_type->setText(0, QString("Тип: %1").arg(typeName));
            entry_class->setText(0, QString("Класс: %1").arg(className));
            qsection->addChild(entry);
        }



    }

    tree->addTopLevelItem(qsection);

    if (acount)
    {
        DnsAnswer * ast = ptr->GetAnswers();
        for (auto i = 0; i < acount; i++)
        {
            const DnsAnswer & value = ast[i];



            auto typeName = DnsStrType(value.type);
            auto className = DnsStrClass(value.cl_name);

            auto timeStr = QDateTime::fromSecsSinceEpoch(value.ttl).time().toString("m минут s секунд");
            auto request_name = reinterpret_cast<const char*>(value.name);
            auto len = QString("%1").arg(value.length);
            QString _data;
            if (value.type == DNS_TYPE_A)
            {
                char addrBuf[ADDR_V4_BUFLEN_MIN];
                FromIPv4Address(addrBuf, ADDR_V4_BUFLEN_MIN, &value.adata.host_addr.address);
                _data = addrBuf;
            }

            else _data = reinterpret_cast<const char*>(value.adata.cname.data);

            auto entry = new QTreeWidgetItem;
            auto entry_name = new QTreeWidgetItem(entry);
            auto entry_type = new QTreeWidgetItem(entry);
            auto entry_class = new QTreeWidgetItem(entry);
            auto entry_time = new QTreeWidgetItem(entry);
            auto entry_len = new QTreeWidgetItem(entry);
            auto entry_data = new QTreeWidgetItem(entry);

            entry->setText(0, tr("%1 тип %2 класс %3 данные: %4").arg(request_name).arg(typeName).arg(className).arg(_data));

            entry_name->setText(0, tr("Имя домена: %1").arg(request_name));
            entry_type->setText(0, tr("Тип: %1").arg(typeName));
            entry_class->setText(0, tr("Класс: %1").arg(className));
            entry_time->setText(0, tr("Валидный (минут, секунд): %1").arg(timeStr));
            entry_len->setText(0, tr("Длина данных: %1 байт").arg(len));
            entry_data->setText(0, tr("Данные: %1").arg(_data));

            asection->addChild(entry);
        }

        tree->addTopLevelItem(asection);
    }

    TransactionIdField->Put(tr("ID транзакции"), idValue);
    TransactionIdField->Commit();
    AddWidget(TransactionIdField);
    AddWidget(flagsTree);
    if (acount)
    {
        QLabel * aValue =       new QLabel(QString("%1").arg(acount));
        ARRField = new kp;
        ARRField->Put(tr("Записи ответов"), aValue);
        ARRField->Commit();
        AddWidget(ARRField);
    }

    if (authCount)
    {
        QLabel * authValue =    new QLabel(QString("%1").arg(authCount));
        AuthRRField = new kp;
        AuthRRField->Put(tr("Административные записи"), authValue);
        AuthRRField->Commit();
        AddWidget(AuthRRField);
    }

    if (addCount)
    {
        QLabel * addValue =     new QLabel(QString("%1").arg(addCount));
        AddRRField = new kp;
        AddRRField->Put(tr("Дополнительные записи"), addValue);
        AddRRField->Commit();
        AddWidget(AddRRField);
    }

    AddWidget(tree);

}

DnsTab::~DnsTab()
{
    delete tree;
    delete flagsTree;
    delete ARRField;
    delete AuthRRField;
    delete AddRRField;
}

void DnsTab::onItemExpanded(QTreeWidgetItem * item)
{

}
