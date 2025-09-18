#include <QVariant>
#include <QMutex>
#include <QSize>
#include <QDateTime>
#include <memory>
#include "packettablemodel.h"
#include "protocolparser.h"


PacketTableModel::PacketTableModel()
{
    locker = std::unique_ptr<QMutex>(new QMutex());
}

PacketTableModel::~PacketTableModel() noexcept
{
    packets.clear();
}

int PacketTableModel::rowCount(const QModelIndex &parent) const
{
    return packets.size();
}

bool PacketTableModel::isEmpty()
{
    return rowCount() == 0;
}

QVariant PacketTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return {};

    auto row = index.row();

    if (row >= packets.size() || row < 0) return {};

    QVariant value{};

    if (role == Qt::DisplayRole) {

        switch (index.column()) {
        case COLUMN_NO: {
            value = QVariant(packets.at(row).GetId());
            break;
        } case COLUMN_DIFF_TIME: {
            auto recv_time = packets.at(row).GetReceiveTime();
            value = QVariant(QDateTime::fromSecsSinceEpoch(recv_time).toLocalTime().toString());
            break;
        } case COLUMN_SRC: {

            const Packet & packet = packets.at(row);
            const Ethernet & ethernet = packet.GetEthernet();

            if (ethernet.hasNextProtocol()) {
                auto proto = packet.GetLayer(Network);
                if (proto) {
                    switch (proto->GetType()) {
                    case CurrentIPv4: {
                        return proto->as<IPv4Holder>()->SourceAddress().data();
                    }
                        case CurrentARP: return ProtocolUtility::IpAsString(proto->as<ARPHolder>()->SourceIP());
                    }
                }
            }

            return "unknown source";
        } case COLUMN_DST: {
            const Packet & packet = packets.at(row);
            const Ethernet & ethernet = packet.GetEthernet();

            if (ethernet.hasNextProtocol()) {
                auto proto = packet.GetLayer(Network);
                if (proto) {
                    switch (proto->GetType()) {
                    case CurrentIPv4: {
                        return proto->as<IPv4Holder>()->DestinationAddress().data();
                    }
                        case CurrentARP: return ProtocolUtility::IpAsString(proto->as<ARPHolder>()->DestinationIP());
                    }
                }
            }

            return "unknown destination";
            break;
        } case COLUMN_PROTO: {

            const Packet & packet = packets.at(row);
            const Ethernet & ethernet = packets.end()->GetEthernet();

            if (!packet.IsProtosEmpty()) {
                return ProtocolUtility::NameOfProtocol(packet.Last());
            }

            return "Ethernet";
        } case COLUMN_LEN: {
            return quint64(packets.at(row).GetActualLen());
        } case COLUMN_INFO: {
            const Packet & packet = packets.at(row);
            //const Ethernet & ethernet = packet.GetEthernet();
            if (!packet.IsProtosEmpty()) {
                return ProtocolUtility::DescOfProtocol(packet.Last());
            }
            return "<info>";
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

void PacketTableModel::append(Packet & packet)
{
    std::size_t older = packets.size();
    beginInsertRows(QModelIndex(), older, older);
    packets.push_back(std::move(packet));
    emit countChanged(packets.size(), packets.capacity());
    endInsertRows();
}

void PacketTableModel::clear() noexcept
{
    beginResetModel();
    packets.clear();
    endResetModel();
}


bool PacketTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);

    beginResetModel();
    packets.clear();
    endResetModel();
    return true;
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


