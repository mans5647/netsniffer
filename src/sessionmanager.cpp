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
#include "packettablemodel.h"
#include "myhexview.h"
#include "sortingproxymodel.h"
#include "ui_mainwindow.h"



SessionManager * SessionManager::instance;

SessionManager::SessionManager()
{
    saveChanges = new QMessageBox();
    saveChanges->setInformativeText("Вы хотите сохранить ранее захваченные пакеты?");
    saveChanges->setStandardButtons(QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    m_interface = nullptr;
    capturing_handle = nullptr;
    fileDumper = nullptr;
    framesModel = new PacketTableModel();
    mtx = new QMutex();
    mf_dialog = new QFileDialog();
    mf_dialog->setFileMode(QFileDialog::Directory);
    mf_dialog->setWindowTitle(QObject::tr("Выберите папку для сохранения ..."));
    cpt_thread = nullptr;
    saveFile = false;
    readThread = nullptr;

}

void SessionManager::capture_thread(pcap_t** handle)
{
    int res;
    pcap_pkthdr *hdr;
    const uint8_t * data;


    static int f_num;
    f_num = 1;
    while ((res = pcap_next_ex(*handle, &hdr, &data)) >= 0)
    {
        if (QThread::currentThread()->isInterruptionRequested())
        {
            break;
        }

        if (res == 0) continue;

        pcap_dump((uint8_t*)fileDumper, hdr, data);
        FrameInfo frame{};

        const char *m_ptr = (const char*)data;
        frame.alt_time = hdr->ts.tv_usec;

        frame.copy = QByteArray(m_ptr, hdr->caplen);
        frame.total_length = hdr->len;

        frame.cap_len = hdr->caplen;
        frame.f_num = f_num;

        frame.recv_time = hdr->ts.tv_sec;
        frame.p_ref = new Packet{};

        ParseFrame(&frame, data);
        framesModel->append(frame);


        emit countUpdated();
        f_num++;
    }


}



void SessionManager::StartCapture()
{

    if (capturing_handle)
    {
        pcap_close(capturing_handle);
    }

    opendevice();

    if (fileDumper) pcap_dump_close(fileDumper);

    if (saveFile)
    {
        FreeResources();
        saveFile = false;
    }

    if (!saveFile && framesModel->rowCount() > 0)
    {
        LiveCapture();
    }
    else open_new_session();
}


bool SessionManager::IsOpened()
{
    return (capturing_handle) ? true : false;
}




void SessionManager::ParseFrame(FrameInfo * frame, const uint8_t * data)
{

    ether_header * ether = (ether_header*)data;
    Ethernet ethernet{ether};

    frame->p_ref->setEthernet(ethernet);

    bool __continue = Ethernet::hasNextProtocol(frame->p_ref->getEthernet());

    if (!__continue) return;

    const uint8_t * payload_data;
    int payload_size = 0;
    ParseNetworkLayer(frame, (data + ETH_HEADER_SIZE));
    ParseTransportLayer(frame, (data + ETH_HEADER_SIZE));


    ProtocolHolder* last = frame->p_ref->Last();

    uint16_t transport_header_size = 0;
    uint16_t net_header_size = 0;

    switch (last->type)
    {
    case CurrentTCP:
    {
        transport_header_size = last->tcp_header.ExtractHeaderSize();

        break;
    }
    case CurrentUDP:
    {
        transport_header_size = last->udp_header.GetHeaderSize();
        break;
    }
    }

    auto first = frame->p_ref->First();
    auto net_layer = GetNetLayerProto(&first);

    if (net_layer->type == CurrentIPv4)
    {
        net_header_size = net_layer->IP4_header.ExtractIHL() * 4;
    }

    payload_size = GetPayloadSize(net_layer,net_header_size, transport_header_size, net_layer->type);

    if (payload_size > 0)
    {
        payload_data = (data + ETH_HEADER_SIZE + net_header_size + transport_header_size);
        uint16_t sport = 0, dport = 0, maybe_wellknown_port = 0;
        switch (last->type)
        {
        case CurrentTCP:
        {
            last->tcp_header.SetPayloadLength(payload_size);
            sport = last->tcp_header.ExtractSPort();
            dport = last->udp_header.ExtractDPort();
            break;
        }
        case CurrentUDP:
        {
            last->udp_header.SetPayloadLength(payload_size);
            sport = last->udp_header.ExtractSPort();
            dport = last->udp_header.ExtractDPort();
            break;
        }
        }


        maybe_wellknown_port = std::min(sport, dport);
        ParseApplicationLayerProto(frame, payload_data, maybe_wellknown_port);
    }


}

ether_header SessionManager::ParseEthernetHeader(const uint8_t * data)
{
    return *(ether_header*)(data);
}

void SessionManager::ParseNetworkLayer(FrameInfo * frame, const uint8_t * data)
{
    auto EtherType = frame->p_ref->getEthernet().getEtherType();


    switch (EtherType)
    {
    case H_PROTO_IP4:
    {
        ProtocolParser::ParseIP4(frame->p_ref,data);
        break;
    }
    case H_PROTO_ARP:
    {
        ProtocolParser::ParseARP(frame->p_ref, data);
        break;
    }
    case H_PROTO_IP6:
    {
        ProtocolParser::ParseIP6(frame->p_ref, data);
        break;
    }
    }
}

void SessionManager::ParseTransportLayer(FrameInfo * frame, const uint8_t * data)
{
    ProtocolHolder * head = frame->p_ref->First();

    auto holder = GetNetLayerProto(&head);

    switch (holder->type)
    {
        case CurrentIPv4:
        {
            auto headerSize = holder->IP4_header.ExtractIHL() * 4;

            auto transport_layer_type = holder->IP4_header.ExtractNextProto();

            if (transport_layer_type == TCP_NEXT)
            {
                ProtocolParser::ParseTCP(frame, (data + headerSize));
            }
            else if (transport_layer_type == UDP_NEXT)
            {
                ProtocolParser::ParseUDP(frame, (data + headerSize));
            }

            else if (transport_layer_type == ICMP_NEXT)
            {
                ProtocolParser::ParseICMP(frame, (data + headerSize));
            }


            break;
        }

        case CurrentIPv6:
        {
            break;
        }


        case CurrentARP:
        {
            break;
        }
    }
}

void SessionManager::ParseApplicationLayerProto(FrameInfo * frame, const uint8_t * payload, uint32_t minport)
{
    switch (minport)
    {
    case HTTP:
    {
        ProtocolParser::ParseHTTP(frame, payload);
        break;
    }
    case HTTPS:
    {
        break;
    }
    case DNS:
    {
        ProtocolParser::ParseDNS(frame, payload);
        break;
    }
    default:
    {

        break;
    }
    }

}

SessionManager::~SessionManager()
{
    pcap_close(capturing_handle);
    delete saveChanges;
    delete framesModel;
    delete instance;
}

void SessionManager::LoadCaptureFile()
{
    QString fname = QFileDialog::getOpenFileName(nullptr, tr("Выбрать файл .pcap"), QDir::current().path(),
                                                                        tr("TCPDump/Wireshark (*.pcap)"));
    open_file_for_read(fname.toLatin1().constData());
}

void SessionManager::mock()
{
    qDebug() << "Finish";
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
    emit modelClearStarted();
    framesModel->clear();
    emit modelClearFinished();
    if (cpt_thread)
    {
        delete cpt_thread;
        cpt_thread = nullptr;
    }
}

void SessionManager::setFileWritePath(const QString &absolute_path)
{
    old_path = this->absolute_path;
    this->absolute_path = absolute_path;
}

QAbstractItemModel *SessionManager::getModel()
{
    return framesModel;
}

void SessionManager::StopCapture(bool __unused)
{
    Q_UNUSED(__unused)
    if (cpt_thread) cpt_thread->requestInterruption();
    emit statusChanged(CaptureStatus::Stopped);
}

void SessionManager::opendevice()
{
    if (m_interface)
    {
        capturing_handle = pcap_open(m_interface->getName().constData(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, local_error_buf);
    }
}

void SessionManager::open_new_session()
{
    if (fileDumper) pcap_dump_close(fileDumper);
    fileDumper = pcap_dump_open(capturing_handle, absolute_path.toLatin1().constData());
    auto type = pcap_datalink(capturing_handle);
    cpt_thread = nullptr;
    switch (type)
    {
    case DLT_NULL: break;
    case DLT_EN10MB: cpt_thread = QThread::create(&SessionManager::capture_thread, this, &capturing_handle); break;
    }

    if (cpt_thread)
    {
        saveFile = false;
        emit statusChanged(CaptureStatus::Started);
        cpt_thread->start();
    }
}

pcap_t *SessionManager::getOpenHandle()
{
    return capturing_handle;
}

void SessionManager::setInterface(const InterfaceItem **item)
{
    m_interface = (*item);
}

void SessionManager::LiveCapture()
{
    int action = saveChanges->exec();
    switch (action)
    {
    case QMessageBox::Save:
    {

        if (fileDumper)
                pcap_dump_close(fileDumper);


        SaveCaptureFile();

        if (RemoveTempFile())
        {
                qDebug() << "Temporary file " << absolute_path << "was removed ...";
                emit fileRemoved();
        }
        else qDebug() << "Not removed";


        FreeResources();
        open_new_session();

        break;
    }
    case QMessageBox::Discard:
    {
        if (fileDumper)
                pcap_dump_close(fileDumper);

        if (RemoveTempFile())
        {
                qDebug() << "Temporary file " << absolute_path << "was removed ...";
                emit fileRemoved();
        }
        else qDebug() << "Not removed";

        FreeResources();

        open_new_session();
        break;
    }
    case QMessageBox::Cancel:
    {
        break;
    }
    }
}

void SessionManager::open_file_for_read(const char *filename)
{
    if (capturing_handle) pcap_close(capturing_handle);

    capturing_handle = pcap_open_offline(filename, errorbuf);

    if (!capturing_handle)
    {
        qDebug() << errorbuf;
    }
    else
    {
        FreeResources();
        saveFile = true;
        auto type = pcap_datalink(capturing_handle);
        bool isReady = false;
        switch (type)
        {
        case DLT_NULL: break;
        case DLT_EN10MB: isReady = true; break;
        }

        if (isReady)
        {

            readThread = QThread::create(&SessionManager::ReadAllPacketsToModel, this);
                connect(readThread, &QThread::started, this, [=] () {
                emit modelPopulateStarted();
            });
            connect(readThread, &QThread::finished, this, [=] () {
                    emit modelPopulateFinished();

                });

            emit got_filename(QString(filename));
            readThread->start();
        }
    }
}

void SessionManager::ReadAllPacketsToModel()
{
    int res;
    pcap_pkthdr *hdr;
    const uint8_t * data;

    static int f_num;
    f_num = 1;

    qDebug() << "Filling model ...";

    while ((res = pcap_next_ex(capturing_handle, &hdr, &data)) >= 0)
    {
        FrameInfo frame{};

        const char *m_ptr = (const char*)data;
        frame.alt_time = hdr->ts.tv_usec;

        frame.copy = QByteArray(m_ptr, hdr->caplen);
        frame.total_length = hdr->len;

        frame.cap_len = hdr->caplen;
        frame.f_num = f_num;

        frame.recv_time = hdr->ts.tv_sec;
        frame.p_ref = new Packet{};

        ParseFrame(&frame, data);
        framesModel->append(frame);
        f_num++;
    }

    qDebug() << "Model filled ...";
}

void SessionManager::setModel()
{
    //mainWindowRef->GetUI()->PacketView->setModel(framesModel);
}

