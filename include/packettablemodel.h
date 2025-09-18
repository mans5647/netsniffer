#ifndef PACKETTABLEMODEL_H
#define PACKETTABLEMODEL_H

#include <QObject>
#include <QAbstractItemModel>
#include <QSortFilterProxyModel>
#include <vector>
#include "proto_list.h"

#define COLUMN_NO           0
#define COLUMN_DIFF_TIME    1
#define COLUMN_SRC          2
#define COLUMN_DST          3
#define COLUMN_PROTO        4
#define COLUMN_LEN          5
#define COLUMN_INFO         6
#define COLUMN_COUNT        7

class QMutex;


class PacketTableModel : public QAbstractListModel
{
    Q_OBJECT


public:
    PacketTableModel();
    ~PacketTableModel() noexcept;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    int columnCount(const QModelIndex &parent) const;
    static float calculatePercent(float count, float chunk_of_count);
    void append(Packet &);
    void clear() noexcept;
    bool isEmpty();

    Q_INVOKABLE bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;

    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

signals:

    void modelFreed();
    void countChanged(const size_t current_count, const size_t current_capacity);

private:
    std::vector<Packet> packets;
    std::unique_ptr<QMutex> locker;
};


#endif // PACKETTABLEMODEL_H
