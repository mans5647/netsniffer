#include "packettablemodel.h"
#include "uihelpers.h"
#include <QVariant>
#include <QMutex>
#include <QSize>
#include "protocolparser.h"

PacketTableModel::PacketTableModel(const PacketTableModel & other) : QAbstractListModel()
{
    frames = other.frames;
    frames.squeeze();
}

PacketTableModel::PacketTableModel()
{
    locker = new QMutex();



}

PacketTableModel::~PacketTableModel() noexcept
{
    frames.clear();
}

int PacketTableModel::rowCount(const QModelIndex &parent) const
{
    return frames.size();
}



QVariant PacketTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant{};
    auto row = index.row();

    if (row >= frames.size() || row < 0) return QVariant{};

    QVariant value{};

    if (role == Qt::DisplayRole)
    {
        switch (index.column())
        {
        case COLUMN_NO:
        {
            value = QVariant(frames.at(row).f_num);
            break;
        }
        case COLUMN_DIFF_TIME:
        {

            auto stamp = frames.at(row).recv_time;

            auto tval = std::localtime(&stamp);

            QTime fmt_time{tval->tm_hour, tval->tm_min, tval->tm_sec};

            QString fmt_str = fmt_time.toString();

            value = QVariant(fmt_str);
            break;
        }
        case COLUMN_SRC:
        {

            QString source;

            const Ethernet & ethernet = frames.at(row).p_ref->getEthernet();

            bool result = Ethernet::hasNextProtocol(ethernet);

            if (result)
            {
                auto holder = frames.at(row).p_ref->First();
                auto node = GetNetLayerProto(&holder);

                assert(node);
                if (node->type == CurrentARP)
                {
                    source = node->arp_header.ExtractSrcMac();
                }
                else if (node->type == CurrentIPv4)
                {
                    source = node->IP4_header.ExtractSrcAddr();
                }

                else if (node->type == CurrentIPv6)
                {
                    char addr_buf[V6_BUF_SIZE_MAX];
                    FromIPv6Address(addr_buf, V6_BUF_SIZE_MAX, node->IP6_header.getSourceAddress());
                    source = addr_buf;
                }
            }

            else
            {
                const Ethernet::Mac & ref_src =  ethernet.getSourceMac();

                char mac_src[MAC_PRETTY_NAME];

                sprintf_s(mac_src, MAC_PRETTY_NAME, MAC_FMT,
                          ref_src.at(0), ref_src.at(1), ref_src.at(2), ref_src.at(3), ref_src.at(4), ref_src.at(5));

                source = mac_src;
            }

            value = QVariant(source);
            break;
        }
        case COLUMN_DST:
        {
            QString dest;

            const Ethernet & ethernet = frames.at(row).p_ref->getEthernet();

            bool result = Ethernet::hasNextProtocol(ethernet);


            if (result)
            {
                auto holder = frames.at(row).p_ref->First();
                auto node = GetNetLayerProto(&holder);

                assert(node);


                if (node->type == CurrentARP)
                {
                    dest = node->arp_header.ExtractDstMac();
                }
                else if (node->type == CurrentIPv4)
                {
                    dest = node->IP4_header.ExtractDstAddr();
                }

                else if (node->type == CurrentIPv6)
                {
                    char addr_buf[V6_BUF_SIZE_MAX];
                    FromIPv6Address(addr_buf, V6_BUF_SIZE_MAX, node->IP6_header.getDestinationAddress());
                    dest = addr_buf;
                }
            }

            else
            {
                const Ethernet::Mac & ref_dst =  ethernet.getDestinationMac();

                char mac_dst[MAC_PRETTY_NAME];

                sprintf_s(mac_dst, MAC_PRETTY_NAME, MAC_FMT,
                          ref_dst.at(0), ref_dst.at(1), ref_dst.at(2), ref_dst.at(3), ref_dst.at(4), ref_dst.at(5));

                dest = mac_dst;
            }

            value = QVariant(dest);
            break;
        }
        case COLUMN_PROTO:
        {
            QString protoIDText;
            const Ethernet & ethernet = frames.at(row).p_ref->getEthernet();

            bool result = Ethernet::hasNextProtocol(ethernet);

            if (result)
            {
                auto _last = frames.at(row).p_ref->Last();
                protoIDText = getLastProtocol(_last);
            }

            else
            {
                protoIDText = "Ethernet";
            }

            value = QVariant(protoIDText);
            break;
        }
        case COLUMN_LEN:
        {
            value = QVariant(frames.at(row).total_length);
            break;
        }
        case COLUMN_INFO:
        {
            const Ethernet & ethernet = frames.at(row).p_ref->getEthernet();
            bool result = Ethernet::hasNextProtocol(ethernet);
            QString infoText;


            if (result)
            {
                auto _last = frames.at(row).p_ref->Last();
                infoText = getPacketInfo(_last);
            }

            else
            {
                infoText = "Ethernet description (not implemented 802.3)";
            }

            value = QVariant(infoText);
            break;
        }
        }

    }
    return value;
}

int PacketTableModel::columnCount(const QModelIndex &parent) const
{
    return COLUMN_COUNT;
}

float PacketTableModel::calculatePercent(float count, float chunk_of_count)
{
    return (chunk_of_count / count) * 100.0f;
}

void PacketTableModel::append(const FrameInfo & frame)
{
    locker->lock();
    int newRow = frames.size();
    int lastRow = newRow;
    beginInsertRows(QModelIndex(), lastRow, newRow);
    emit countChanged(frames.size(), frames.capacity());
    frames.append(frame);
    endInsertRows();
    locker->unlock();
}

const FrameInfo &PacketTableModel::get(int index) const
{
    if (index >= frames.size())
        return this->operator [](frames.size() - 1);
    if (index < 0) return this->operator [](0);
    return this->operator [](index);
}

const FrameInfo &PacketTableModel::operator [](int index) const
{
    return frames.at(index);
}

void PacketTableModel::clear() noexcept
{
    beginResetModel();
    frames.clear();
    endResetModel();
}

PacketTableModel::ListType *PacketTableModel::get_list_ptr()
{
    return &frames;
}

bool PacketTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);

    beginResetModel();
    frames.resize(0);
    frames.squeeze();
    endResetModel();

    return true;
}

FrameInfo& PacketTableModel::operator [](int index)
{
    return frames[index];
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        switch (section) {
        case COLUMN_NO:
            return QString(tr("Номер"));
        case COLUMN_DIFF_TIME:
            return QString(tr("Время"));
        case COLUMN_SRC:
            return QString(tr("Источник"));
        case COLUMN_DST:
            return QString(tr("Назначение"));
        case COLUMN_PROTO:
            return QString(tr("Протокол"));
        case COLUMN_LEN:
            return QString(tr("Длина"));
        case COLUMN_INFO:
            return QString(tr("Краткая информация"));
        }
    }

    return QVariant{};
}


