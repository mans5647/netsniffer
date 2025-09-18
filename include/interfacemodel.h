#ifndef INTERFACEMODEL_H
#define INTERFACEMODEL_H

#include "interfaceitem.h"
#include <QAbstractItemModel>
#include <QThread>
#include <vector>

#define COLUMN_SIZE             6

#define COLUMN_FRIENDLY_NAME    0
#define COLUMN_DESC             1
#define COLUMN_TYPE             2
#define COLUMN_RUNNING          3
#define COLUMN_CONN_STATUS      4
#define COLUMN_ADDR_FMT         5

class InterfaceModel : public QAbstractItemModel
{
    Q_OBJECT
public:
    InterfaceModel();

    void ReloadAllDevices();
    void RetrieveDevices(); // reset all devices and re-gets new instances from the system
    bool hasIndex(int row, int column, const QModelIndex &parent = QModelIndex()) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    QModelIndex parent(const QModelIndex &child) const;
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
public slots:
    const InterfaceItem * get(const QModelIndex & index);
    void ResetModel();
signals:
    void errorHappened();
    void devicesRetrieved();
    void modelResetBegin();
    void modelResetEnd();

private:
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * alldevs;
    std::vector<InterfaceItem> interfaces; // deep copy of all interfaces
    void appendItem(InterfaceItem && item);
    QThread * loader;
    bool isLoaded;

#if __linux__
    void retrieveDevicesLinux();
#elif defined(_WIN32)
    void retrieveDevicesWin32();
#endif
};

#endif // INTERFACEMODEL_H
