#include "protocolparser.h"
#include "sessionmanager.h"
#include "packet_row.h"
#include "ports.h"
#include <QWidget>
#include <QFile>
#include <fstream>
#include <algorithm>
#include <QFileDialog>
#include <QDir>
#include <pcap/pcap.h>
#include "packettablemodel.h"
#include "sortingproxymodel.h"
#include "ui_mainwindow.h"

#define MSG_BOX_ERROR_SHOW(title, err) QMessageBox{QMessageBox::Icon::Critical, title, err}.exec();
#define MSG_BOX_INFO_SHOW(title, text) QMessageBox{QMessageBox::Icon::Information, title, text}.exec();


SessionManager * SessionManager::instance;

SessionManager * SessionManager::getInstance()
{
    if (!instance)
    {
        instance = new SessionManager();
    }
    return instance;
}

SessionManager::SessionManager()
{
    save_changes_msgbox = new QMessageBox();
    save_changes_msgbox->setInformativeText("Вы хотите сохранить ранее захваченные пакеты?");
    save_changes_msgbox->setStandardButtons(QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    current_interface = nullptr;
    capture_handle = nullptr;
    file_dumper = nullptr;
    packets = new PacketTableModel();
    file_dialog = new QFileDialog();
    file_dialog->setFileMode(QFileDialog::Directory);
    file_dialog->setWindowTitle(QObject::tr("Выберите папку для сохранения ..."));
    capture_thread = nullptr;
    save_to_file = false;
    read_thread = nullptr;

}

void SessionManager::doCaptureLoop()
{
    int res;
    pcap_pkthdr *hdr;
    const uint8_t * data;


    int frameId;
    frameId = 1;
    ProtocolParser parser;
    while ((res = pcap_next_ex(capture_handle, &hdr, &data)) >= 0)
    {
        if (QThread::currentThread()->isInterruptionRequested())
        {
            break;
        }

        if (res == 0) continue;

        pcap_dump(reinterpret_cast<uint8_t*>(file_dumper), hdr, data);

        std::optional<Packet> packet_o = parser.Parse(frameId, hdr, data);

        if (!packet_o.has_value()) {
            continue;
        }

        packets->append(*packet_o);
        emit CountUpdated();
        frameId++;
    }


}



void SessionManager::StartCapture()
{

    if (capture_handle)
        pcap_close(capture_handle);

    if (file_dumper)
        pcap_dump_close(file_dumper);

    if (!packets->isEmpty())
    {
        switch (save_changes_msgbox->exec())
        {
            case QMessageBox::Save:
            {
                SaveCaptureFile();
                RemoveTempFile();
                break;
            }
            case QMessageBox::Discard:
            {
                RemoveTempFile();
                break;
            }
            case QMessageBox::Cancel:
                return;
        }
    }

    FreeResources();
    OpenNewSession();
}


bool SessionManager::IsOpened()
{
    return (capture_handle) ? true : false;
}




// void SessionManager::parseFrame(FrameInfo * frame, const uint8_t * data)
// {

//     ether_header * ether = (ether_header*)data;
//     Ethernet ethernet{ether};

//     frame->p_ref->setEthernet(ethernet);

//     bool __continue = Ethernet::hasNextProtocol(frame->p_ref->getEthernet());

//     if (!__continue) return;

//     const uint8_t * payload_data;
//     int payload_size = 0;
//     parseNetworkLayer(frame, (data + ETH_HEADER_SIZE));
//     parseTransportLayer(frame, (data + ETH_HEADER_SIZE));


//     ProtocolHolder* last = frame->p_ref->Last();

//     uint16_t transport_header_size = 0;
//     uint16_t net_header_size = 0;

//     switch (last->type)
//     {
//     case CurrentTCP:
//     {
//         transport_header_size = last->tcp_header.ExtractHeaderSize();

//         break;
//     }
//     case CurrentUDP:
//     {
//         transport_header_size = last->udp_header.GetHeaderSize();
//         break;
//     }
//     }

//     auto first = frame->p_ref->First();
//     auto net_layer = GetNetLayerProto(&first);

//     if (net_layer->type == CurrentIPv4)
//     {
//         net_header_size = net_layer->IP4_header.ExtractIHL() * 4;
//     }

//     payload_size = GetPayloadSize(net_layer,net_header_size, transport_header_size, net_layer->type);

//     if (payload_size > 0)
//     {
//         payload_data = (data + ETH_HEADER_SIZE + net_header_size + transport_header_size);
//         uint16_t sport = 0, dport = 0, maybe_wellknown_port = 0;
//         switch (last->type)
//         {
//         case CurrentTCP:
//         {
//             last->tcp_header.SetPayloadLength(payload_size);
//             sport = last->tcp_header.ExtractSPort();
//             dport = last->udp_header.ExtractDPort();
//             break;
//         }
//         case CurrentUDP:
//         {
//             last->udp_header.SetPayloadLength(payload_size);
//             sport = last->udp_header.ExtractSPort();
//             dport = last->udp_header.ExtractDPort();
//             break;
//         }
//         }


//         maybe_wellknown_port = std::min(sport, dport);
//         parseApplicationLayerProto(frame, payload_data, maybe_wellknown_port);
//     }


// }

ether_header SessionManager::parseEthernetHeader(const uint8_t * data)
{
    return *(ether_header*)(data);
}

// void SessionManager::parseNetworkLayer(FrameInfo * frame, const uint8_t * data)
// {
//     auto EtherType = frame->p_ref->getEthernet().getEtherType();


//     switch (EtherType)
//     {
//     case H_PROTO_IP4:
//     {
//         ProtocolParser::ParseIP4(frame->p_ref,data);
//         break;
//     }
//     case H_PROTO_ARP:
//     {
//         ProtocolParser::ParseARP(frame->p_ref, data);
//         break;
//     }
//     case H_PROTO_IP6:
//     {
//         ProtocolParser::ParseIP6(frame->p_ref, data);
//         break;
//     }
//     }
// }

// void SessionManager::parseTransportLayer(FrameInfo * frame, const uint8_t * data)
// {
//     ProtocolHolder * head = frame->p_ref->First();

//     auto holder = GetNetLayerProto(&head);

//     switch (holder->type)
//     {
//         case CurrentIPv4:
//         {
//             auto headerSize = holder->IP4_header.ExtractIHL() * 4;

//             auto transport_layer_type = holder->IP4_header.ExtractNextProto();

//             if (transport_layer_type == TCP_NEXT)
//             {
//                 ProtocolParser::ParseTCP(frame, (data + headerSize));
//             }
//             else if (transport_layer_type == UDP_NEXT)
//             {
//                 ProtocolParser::ParseUDP(frame, (data + headerSize));
//             }

//             else if (transport_layer_type == ICMP_NEXT)
//             {
//                 ProtocolParser::ParseICMP(frame, (data + headerSize));
//             }


//             break;
//         }

//         case CurrentIPv6:
//         {
//             break;
//         }


//         case CurrentARP:
//         {
//             break;
//         }
//     }
// }

// void SessionManager::parseApplicationLayerProto(FrameInfo * frame, const uint8_t * payload, uint32_t minport)
// {
//     switch (minport)
//     {
//     case HTTP:
//     {
//         ProtocolParser::ParseHTTP(frame, payload);
//         break;
//     }
//     case HTTPS:
//     {
//         break;
//     }
//     case DNS:
//     {
//         ProtocolParser::ParseDNS(frame, payload);
//         break;
//     }
//     default:
//     {

//         break;
//     }
//     }

// }

SessionManager::~SessionManager()
{
    pcap_close(capture_handle);
    delete save_changes_msgbox;
    delete packets;
    delete instance;
}

void SessionManager::LoadCaptureFile()
{
    QString fname = QFileDialog::getOpenFileName(nullptr, tr("Выбрать файл .pcap"), QDir::current().path(),
                                                                        tr("TCPDump/Wireshark (*.pcap)"));
    openForRead(fname.toStdString().c_str());
}


bool SessionManager::RemoveTempFile()
{
    QFile deleter{absolute_path};
    bool result = deleter.remove();
    deleter.close();
    return result;
}

void SessionManager::SaveCaptureFile()
{
    QString fname = QFileDialog::getSaveFileName(nullptr, tr("Сохранить дамп"),
                                                    absolute_path,
                                                    tr("TCPDump/Wireshark (*.pcap)"));

    QFile tmp_file{absolute_path};

    tmp_file.copy(fname);
    tmp_file.close();
}

void SessionManager::FreeResources()
{
    emit ModelClearStarted();
    packets->clear();
    emit ModelClearFinished();
    if (capture_thread)
    {
        delete capture_thread;
        capture_thread = nullptr;
    }
}

void SessionManager::SetDumpWritePath(const QString &absolute_path)
{
    old_path = this->absolute_path;
    this->absolute_path = absolute_path;
}

QAbstractItemModel *SessionManager::GetPackets()
{
    return packets;
}

void SessionManager::StopCapture()
{
    if (capture_thread) capture_thread->requestInterruption();
    emit StatusChanged(CaptureStatus::Stopped);
}

void SessionManager::OpenNewSession()
{
    capture_handle = pcap_open_live(current_interface->GetName().toStdString().c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, pcap_error_buf);


    if (!capture_handle) {
#ifdef QT_DEBUG
        qDebug() << "Error while opening device at OpenNewSession(): " << pcap_error_buf;
#else
        MSG_BOX_ERROR_SHOW("Error opening device", pcap_error_buf)
#endif

        return;
    }

    file_dumper = pcap_dump_open(capture_handle, absolute_path.toStdString().c_str());

    if (!file_dumper) {
#ifdef QT_DEBUG
        qDebug() << "Error while opening dump at OpenNewSession()" <<
                    pcap_error_buf;
#else
        MSG_BOX_ERROR_SHOW("Error opening dump file", pcap_error_buf)
#endif
        return;
    }

    capture_thread = nullptr;
    switch (pcap_datalink(capture_handle))
    {
        case DLT_EN10MB:
        {
            capture_thread = QThread::create(&SessionManager::doCaptureLoop, this);
            break;
        }
        default:
        {
            MSG_BOX_ERROR_SHOW("Error retrieving device type", "Device LINK layer is not supported")
            return;
        }
    }

    if (capture_thread)
    {
        save_to_file = false;
        emit StatusChanged(CaptureStatus::Started);
        capture_thread->start();
    }
}

pcap_t *SessionManager::GetRawCaptureHandle()
{
    return capture_handle;
}

void SessionManager::SetInterface(const InterfaceItem * interface)
{
    current_interface = interface;
}

void SessionManager::liveCapture()
{

}

void SessionManager::openForRead(const char *filename)
{
    if (capture_handle) pcap_close(capture_handle);

    capture_handle = pcap_open_offline(filename, pcap_error_buf);

    if (!capture_handle)
    {
#ifdef QT_DEBUG
        qDebug() << "Error opening dump for read: " << pcap_error_buf;
#else
        MSG_BOX_ERROR_SHOW("Error opening dump for read", pcap_error_buf)
#endif
    }
    else
    {
        FreeResources();
        save_to_file = true;
        auto type = pcap_datalink(capture_handle);
        bool isReady = false;
        switch (type)
        {
        case DLT_NULL: break;
        case DLT_EN10MB: isReady = true; break;
        }

        if (isReady)
        {

            read_thread = QThread::create(&SessionManager::readAllPacketsToModel, this);
                connect(read_thread, &QThread::started, this, [=] () {
                emit ModelPopulateStarted();
            });
            connect(read_thread, &QThread::finished, this, [=] () {
                    emit ModelPopulateFinished();
                });

            emit FileNameFetched(QString(filename));
            read_thread->start();
        }
    }
}

void SessionManager::readAllPacketsToModel()
{
    int res;
    pcap_pkthdr *hdr;
    const uint8_t * data;

    static int f_num;
    f_num = 1;

#ifdef QT_DEBUG
    qDebug() << "reading packets to data model started ...";
#else
#endif

    while ((res = pcap_next_ex(capture_handle, &hdr, &data)) >= 0)
    {
        // FrameInfo frame{};

        // const char *m_ptr = (const char*)data;
        // frame.alt_time = hdr->ts.tv_usec;

        // frame.copy = QByteArray(m_ptr, hdr->caplen);
        // frame.total_length = hdr->len;

        // frame.cap_len = hdr->caplen;
        // frame.f_num = f_num;

        // frame.recv_time = hdr->ts.tv_sec;
        // frame.p_ref = new Packet{};

        // parseFrame(&frame, data);
        // packets->append(frame);
        // f_num++;
    }

#ifdef QT_DEBUG
    qDebug() << "reading packets to data model finished ...";
#else
#endif

}
