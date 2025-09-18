// #ifndef PROTOCOLDETAILTAB_H
// #define PROTOCOLDETAILTAB_H

// #include <QObject>
// #include <QWidget>
// #include <QLayout>
// #include <QScrollArea>
// #include <QTreeWidget>
// #include <iostream>
// #include <utility>
// #include "keyvaluepairwidget.h"
// #include "TabInfo.h"
// #include "proto_list.h"

// using kp = KeyValuePairWidget;
// using kp_ptr = KeyValuePairWidget *;
// class DnsRecordsSection;


// class ParentArea : public QScrollArea
// {
//     Q_OBJECT
// public:
//     explicit ParentArea(QWidget * parent = nullptr);
//     void SetChild(QWidget *);

//     ~ParentArea();
// public slots:
//     void UpdateVerticalBar(int, int);
//     void UpdateHorizontalBar(int, int);
// };

// class BaseTabWidget : public QWidget
// {
// public:
//     explicit BaseTabWidget(ProtocolHolder *,QWidget* parent = nullptr);
//     void AddWidget(QWidget *);

//     virtual void commit() {}

//     virtual ~BaseTabWidget();

// protected:
//     QVBoxLayout * layout;
//     ProtocolHolder * m_ptr;
//     QSpacerItem * endSpace;
// };


// class GeneralInfoTab : public BaseTabWidget
// {
// public:
//     GeneralInfoTab(const FrameInfo *,QWidget * parent = nullptr);
//     void commit() override;

//     ~GeneralInfoTab();

// private:
//     KeyValuePairWidget * number, * utc_arrival, * local_arrival, * epoch;
//     KeyValuePairWidget * len, *captureLen, *protocols;

//     QLabel * numberValue, * utcValue, *epoch_value ,*localValue , * lenValue, * captureLenValue;
//     QLabel * protocolsInFrameValue;

//     const FrameInfo * frame;


// };


// class EthernetDetailTab : public BaseTabWidget
// {
// public:
//     explicit EthernetDetailTab(const Ethernet *, QWidget * parent = nullptr);
//     void commit() override;

//     ~EthernetDetailTab();
// private:
//     const Ethernet * value;
//     KeyValuePairWidget * src, *dst, *proto;
//     QLabel * srcValue, * dstValue, * protoValue;
// };


// class V4_Tab : public BaseTabWidget
// {

// public:
//     explicit V4_Tab(ProtocolHolder *);
//     void commit() override;
//     ~V4_Tab();
// private:

//     ProtocolHolder * value;

//     KeyValuePairWidget * version_field, * header_len_field, * dscp_field, * ecn_field;
//     KeyValuePairWidget * total_length_field, * id_field;

//     KeyValuePairWidget * flags_common_field;

//     KeyValuePairWidget * flags_reserved, * flags_dont_fragment, * flags_more_fragments;

//     KeyValuePairWidget * fragment_offset_field;
//     KeyValuePairWidget * ttl_field;
//     KeyValuePairWidget * protocol_field;
//     KeyValuePairWidget * checksum_field;
//     KeyValuePairWidget * source_field;
//     KeyValuePairWidget * destination_field;

//     static constexpr auto MAX_PROPERTIES = 16;


// #define IPV_IDX 0
// #define IPV_HLEN_IDX 1
// #define IP_DSCP_IDX 2
// #define IP_ECN_IDX 3
// #define IP_TLEN_IDX 4
// #define IP_ID_IDX 5
// #define IP_FCOMMON_IDX 6
// #define IP_R_IDX 7
// #define IP_D_IDX 8
// #define IP_M_IDX 9
// #define IP_OFF_IDX 10
// #define IP_TTL_IDX 11
// #define IP_P_IDX 12
// #define IP_CSUM_IDX 13
// #define IP_SRC_IDX 14
// #define IP_DST_IDX 15
// };


// class ArpTab : public BaseTabWidget
// {
// public:
//     explicit ArpTab(ProtocolHolder *);
//     void commit() override;
//     ~ArpTab();
// private:
//     kp_ptr htype_field;
//     kp_ptr ptype_field;
//     kp_ptr hsize;
//     kp_ptr psize;
//     kp_ptr opcode_field;
//     kp_ptr macsender_field;
//     kp_ptr ipsender_field;
//     kp_ptr macrecv_field;
//     kp_ptr iprecv_field;

//     QLabel * htypevalue;
//     QLabel * ptypevalue;
//     QLabel * hszvalue;
//     QLabel * pszvalue;
//     QLabel * opcode_value;
//     QLabel * media_value_sender;
//     QLabel * address_value_sender;
//     QLabel * media_value_recv;
//     QLabel * address_value_recv;

//     ProtocolHolder * value;
// };


// class TCPTab : public BaseTabWidget
// {
// public:
//     explicit TCPTab(ProtocolHolder*);
//     void commit() override;
//     ~TCPTab();
//     static const int TCP_FLAGS_COUNT = 8;
// private:

//     kp_ptr src_field, dst_field, seq_field, ack_field;
//     kp_ptr hlen_field, flags_formatted_field;

//     kp_ptr flags_pair_fields[TCP_FLAGS_COUNT];
//     kp_ptr wnd_size_field;

//     kp_ptr checksum_ptr_field;
//     kp_ptr urgent_field;


//     QLabel * flags_pair_values [TCP_FLAGS_COUNT];
//     QLabel * src_value, *dst_value, * seq_value, *ack_value;
//     QLabel * hlen_value, * flags_formatted_value;
//     QLabel * wnd_size_value, * chk_sum_value, * urgent_value;
// };


// class UDPTab : public BaseTabWidget
// {
// public:
//     explicit UDPTab(ProtocolHolder *);
//     void commit() override;
//     ~UDPTab();
// private:
//     kp_ptr SourcePort_field;
//     kp_ptr DestinationPort_field;
//     kp_ptr Length_field;
//     kp_ptr Checksum_field;

//     QLabel * SourcePort_value;
//     QLabel * DestinationPort_value;
//     QLabel * Length_value;
//     QLabel * Checksum_value;
// };


// class ICMPTab : public BaseTabWidget
// {
// public:
//     explicit ICMPTab(ProtocolHolder*);
//     void commit() override;
//     ~ICMPTab();

// private:

//     kp_ptr TypeField;
//     kp_ptr CodeField;
//     kp_ptr ChecksumField;
//     kp_ptr DataField;

//     QTreeWidget * tree;

//     QTreeWidgetItem * expander; // data expander

//     QTreeWidgetItem * data_ip_header_child; // ip header
//     QTreeWidgetItem * data_raw_child; // custom data
// };


// class DnsTab : public BaseTabWidget
// {
//     Q_OBJECT
// public:
//     explicit DnsTab(ProtocolHolder*);
//     void commit() override;
//     ~DnsTab();

// private:
//     QTreeWidget * tree;
//     QTreeWidgetItem * asection;
//     QTreeWidgetItem * qsection;


//     kp_ptr TransactionIdField;
//     QTreeWidget * flagsTree;
//     kp_ptr QCountField, ARRField, AuthRRField, AddRRField;

// signals:

//     void sectionSizeChanged(int min, int totalLength);

// private slots:
//     void onItemExpanded(QTreeWidgetItem*);
// };



// union tab
// {
//     GeneralInfoTab * pinfo;
//     EthernetDetailTab * eth;
//     V4_Tab * v4;
//     ArpTab * _arp;
//     TCPTab * _tcp;
//     UDPTab * _udp;
//     ICMPTab * _icmp;
//     DnsTab * _dns;
// };


// enum class TabType
// {
//     None,
//     General,
//     Ethernet,
//     V4,
//     V6,
//     ARP,
//     ICMP,
//     TCP,
//     UDP,
//     DNS,
//     HTTP, // not supported yet
//     HTTPS,// not supported yet
//     DHCP, // not supported yet
//     IGMP, // not supported yet
// };




// class GenericTab : public QObject
// {
//     Q_OBJECT
// public:
//     GenericTab()
//     {
//         type = TabType::None;
//         mainWidget = nullptr;
//     }
//     GenericTab(TabType,const FrameInfo*, ProtocolHolder *); // constructs Tab with underlying class specified by type

//     GenericTab(GenericTab &&) noexcept; // move cstor
//     GenericTab(const GenericTab &) = delete; // delete prevents copy

//     ParentArea * getMainWidget();
//     tab* getTab();
//     TabType getType();

//     ~GenericTab();
// private:
//     TabType type;
//     ParentArea * mainWidget;
//     ProtocolHolder * value_maybe;
//     tab internal;
// };

// #endif // PROTOCOLDETAILTAB_H
