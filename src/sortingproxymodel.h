#ifndef SORTINGPROXYMODEL_H
#define SORTINGPROXYMODEL_H

#define COLUMN_COUNT 7
#define COLUMN_NO           0
#define COLUMN_DIFF_TIME    1
#define COLUMN_SRC          2
#define COLUMN_DST          3
#define COLUMN_PROTO        4
#define COLUMN_LEN          5
#define COLUMN_INFO         6
#include <QSortFilterProxyModel>
#include <QMutex>


class PacketTableModel;
class MainWindow;
enum protocol_t;
enum class SortType
{
    Protocol,
    Property
};

class SortingProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    SortingProxyModel(QObject * parent = nullptr);

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    Q_INVOKABLE bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;

    bool locked();
    void make_connects();
public slots:
    void refilter(const QString &, bool);
    void apply_filter(const QString &, bool);

    void setLock(bool);
    void setLocked();
    void setUnlocked();

signals:

    void filterCountChanged(float count, float chunk);
    void filteringBegan();
    void filteringEnded();
protected:
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;

private:
    QString filterExpr;
    QThread * sortThread;
    QThread * filterThread;
    QThread * prev;
    QMutex  * filterMutex;

    bool isSortThreadFinished;
    bool isFilterThreadFinished;

    bool enabled;
    bool locked_;
    PacketTableModel * m_model;
    MainWindow * wnd;
    mutable int filteredCount;
    int totalCount;


    mutable struct SortingEntity
    {
        SortType __type;

        union sortingDataUnderlyingValue {
            protocol_t proto;
            int property;
        };

        sortingDataUnderlyingValue __value;
        bool has_set;
    } sortingEntity;

};

#endif // SORTINGPROXYMODEL_H
