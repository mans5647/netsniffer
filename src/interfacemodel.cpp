#include "interfacemodel.h"
#include "helpers.h"
#include "proto.h"
#include <QRegularExpression>

#pragma comment(lib, "IPHLPAPI.lib")

InterfaceModel::InterfaceModel()
{
    loader = QThread::create(&InterfaceModel::RetrieveDevices, this);
    connect(loader, &QThread::started,  this,  [this]()   { emit modelResetBegin(); });
    connect(loader, &QThread::finished, this, [this]()  { emit modelResetEnd(); isLoaded = true; });
    isLoaded = true;
}

void InterfaceModel::ReloadAllDevices()
{
    if (!isLoaded) return;


    loader = QThread::create(&InterfaceModel::RetrieveDevices, this);
    connect(loader, &QThread::started,  this,  [this]()   { emit modelResetBegin(); });
    connect(loader, &QThread::finished, this, [this]()  { emit modelResetEnd(); isLoaded = true; });
    isLoaded = false;
    loader->start();
}

void InterfaceModel::ResetModel()
{
    beginResetModel();
    interfaces.clear();
    endResetModel();
}

void InterfaceModel::appendItem(InterfaceItem &&item)
{
    int last_new = rowCount();
    int last = rowCount();
    beginInsertRows(QModelIndex(), last, last_new);
    endInsertRows();
}

void InterfaceModel::RetrieveDevices()
{

    ResetModel();
    int status = pcap_findalldevs(&alldevs, errbuf);

    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    PIP_ADAPTER_ADDRESSES pCurrAddress = nullptr;
    ULONG buflen = 100000;
    if (status == PCAP_ERROR)
        emit errorHappened();
    else
    {
        pcap_if_t * node = alldevs;

        pAddresses = new IP_ADAPTER_ADDRESSES[buflen];
        int family = AF_UNSPEC;
        int flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
        size_t result = GetAdaptersAddresses(family,flags, nullptr, pAddresses, &buflen);

        while (node)
        {
            int lastRow = int(interfaces.size());
            int last = lastRow;

            beginInsertRows(QModelIndex(), last, lastRow);
            interfaces.emplace_back(node);
            endInsertRows();
            node = node->next;
        }

        if (result == ERROR_SUCCESS)
        {
            pCurrAddress = pAddresses;

            while (pCurrAddress)
            {
                QString adapterName = pCurrAddress->AdapterName;

                for (auto i = interfaces.begin(); i != interfaces.end(); i++)
                {
                    QString ifacename_raw = i->getName();
                    size_t pos = ifacename_raw.indexOf(QChar('_'));
                    if (pos != -1)
                    {
                        QString ifacename_normal = ifacename_raw.sliced(pos + 1);
                        QRegularExpression lp_matcher{"[lL]oopback", QRegularExpression::CaseInsensitiveOption};
                        if (ifacename_normal == adapterName)
                            i->setFriendlyName(QString::fromWCharArray(pCurrAddress->FriendlyName));
                        else if (lp_matcher.match(ifacename_normal).hasMatch())
                            i->setFriendlyName("Loopback");

                    }

                }

                pCurrAddress = pCurrAddress->Next;
            }

        }

        delete [] pAddresses;
        emit devicesRetrieved();

    }
}

bool InterfaceModel::hasIndex(int row, int column, const QModelIndex &parent) const
{
    if (row < 0 || column < 0)
        return false;
    return row < rowCount(parent) && column < columnCount(parent);
}

QModelIndex InterfaceModel::index(int row, int column, const QModelIndex &parent) const
{
    return hasIndex(row, column, parent) ? createIndex(row, column) : QModelIndex();
}

QModelIndex InterfaceModel::parent(const QModelIndex &child) const
{
    return QModelIndex();
}

int InterfaceModel::rowCount(const QModelIndex &parent) const
{
    return int(interfaces.size());
}

int InterfaceModel::columnCount(const QModelIndex &parent) const
{
    return COLUMN_SIZE;
}

QVariant InterfaceModel::data(const QModelIndex &index, int role) const
{
    QVariant value{};
    if (role == Qt::DisplayRole)
    {
        int column = index.column();
        int row = index.row();

        switch (column)
        {
        case COLUMN_FRIENDLY_NAME:
        {
            value.setValue(interfaces.at(row).getFriendlyName());
            break;
        }
        case COLUMN_DESC:
        {
            value.setValue(interfaces.at(row).getDescription());
            break;
        }
        case COLUMN_TYPE:
        {
            DeviceType type = interfaces.at(row).getType();

            switch (type)
            {
            case DeviceType::Unknown:   value.setValue(tr("Неизвестное устройство"));  break;
            case DeviceType::Wireless:  value.setValue(tr("Беспроводное устройство")); break;
            case DeviceType::Ethernet:  value.setValue(tr("Ethernet")); break;
            case DeviceType::Loopback:  value.setValue(tr("Loopback")); break;
            case DeviceType::Other:     value.setValue(tr("Другое"));    break;
            }

            break;
        }
        case COLUMN_RUNNING:
        {

            const InterfaceItem & ref = interfaces.at(row);
            auto flags = ref.getFlags();
            if (ref.is_running() && !(flags & PCAP_IF_UP))
                value.setValue(tr("Установлено, но не запущено"));
            else value.setValue(tr("Установлено и запущено"));
            break;
        }
        case COLUMN_CONN_STATUS:
        {

            const InterfaceItem & ref = interfaces.at(row);
            auto flags = ref.getFlags();

            if (flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
                value.setValue(tr("Подключено"));
            else if (flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
                value.setValue(tr("Отключено"));
            else if (flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)
                value.setValue(tr("Не применимо"));
            else value.setValue(tr("Неизвестно"));
            break;
        }
        case COLUMN_ADDR_FMT:
        {
            QString fmt;
            const InterfaceItem & device = interfaces.at(row);
            InterfaceItem::ConstIteratorType begin = interfaces.at(row).firstAddress();
            InterfaceItem::ConstIteratorType end = interfaces.at(row).lastAddress();

            for (; begin != end; begin++)
            {
                if (begin->HasAddress())
                {
                    const sockaddr * setAddr = begin->getAddr();
                    if (setAddr->sa_family == AF_INET)
                    {
                        char buf[16];
                        const sockaddr_in * Addr4 = (const sockaddr_in*)setAddr;
                        inet_ntop(AF_INET, &Addr4->sin_addr, buf, 16);

                        fmt += buf;
                        fmt += " , ";
                    }
                    else if (setAddr->sa_family == AF_INET6)
                    {
                        char buf[V6_BUF_SIZE_MAX];
                        const sockaddr_in6 * Addr6 = (const sockaddr_in6*)setAddr;
                        inet_ntop(AF_INET6, &Addr6->sin6_addr, buf, V6_BUF_SIZE_MAX);
                        fmt += buf;
                        fmt += " , ";
                    }
                }
            }

            if (device.getType() == DeviceType::Loopback)
            {
                fmt = "127.0.0.1";
            }

            value.setValue(fmt);
            break;
        }
        }

    }


    return value;
}

QVariant InterfaceModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    QVariant value;
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal)
    {
        switch (section)
        {
            case COLUMN_FRIENDLY_NAME: value.setValue(tr("Понятное имя")); break;
            case COLUMN_DESC: value.setValue(tr("Описание")); break;
            case COLUMN_TYPE: value.setValue(tr("Тип адаптера")); break;
            case COLUMN_RUNNING: value.setValue(tr("Текущее положение")); break;
            case COLUMN_CONN_STATUS: value.setValue(tr("Подключение")); break;
            case COLUMN_ADDR_FMT: value.setValue(tr("Адреса"));
        }
    }

    else if (role == Qt::TextAlignmentRole)
        value.setValue(Qt::AlignLeft);

    return value;
}

const InterfaceItem * InterfaceModel::get(const QModelIndex &index)
{
    return hasIndex(index.row(), index.column()) ? &interfaces.at(index.row()) : nullptr;
}
