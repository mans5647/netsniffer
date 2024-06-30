#include "sortingproxymodel.h"
#include "packettablemodel.h"
#include <QWidget>
#include <QThread>
#include <chrono>
#include <QRegularExpression>
#include <QRegularExpressionMatch>

SortingProxyModel::SortingProxyModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    enabled = false;
    m_model = nullptr;
    filteredCount = 0;
    totalCount = 0;
    isSortThreadFinished = true;
    isFilterThreadFinished = true;

    locked_ = false;

    filterThread = nullptr;
}

void SortingProxyModel::refilter(const QString & filterExpr, bool enabled)
{
    this->filterExpr = filterExpr;
    this->enabled = enabled;
    filteredCount = 0;

    invalidateFilter();
    float percent = 0.0f;
    int rowCount = sourceModel()->rowCount();
    if (enabled)
    {
        if (rowCount == 0)
        {
            percent = 0.0f;
        }
        else
        {
            percent = PacketTableModel::calculatePercent((float)rowCount, filteredCount);
        }
    }
    else
    {
        percent = 100.0f;
    }

    emit filterCountChanged((float)rowCount, (float)filteredCount);
}

void SortingProxyModel::apply_filter(const QString & pattern, bool enabled)
{
    if (isFilterThreadFinished)
    {
        delete filterThread;
        filterThread = nullptr;
    }
    else return;

    if (locked())
    {

    }
    else
    {
        filterThread = QThread::create(&SortingProxyModel::refilter, this, pattern, enabled);
        emit filteringBegan();
        connect(filterThread, &QThread::finished, this, [=] () {
            emit filteringEnded();
            isFilterThreadFinished = true;
            });
        isFilterThreadFinished = false;
        filterThread->start();
    }
//    if (isFilterThreadFinished)
//    {
//        filterThread->quit();
//        filterThread->wait();
//        delete filterThread;
//    }

//    else
//        return;

//    wnd->resetHexPanel();
//    wnd->resetProtoViewPanel();
//    auto workFilter = [&,this] ()
//    {
//        auto model = SessionManager::getInstance()->getModel();
//        setSourceModel(model);
//        setDynamicSortFilter(false);
//        wnd->GetUI()->PacketView->setModel(this);
//        wnd->GetUI()->PacketView->setSortingEnabled(true);

//        //sort(0, Qt::AscendingOrder);

//        filterThread = QThread::create(&SortingProxyModel::refilter, this,pattern, enabled);
//        connect(filterThread, &QThread::finished, this, [&] () { isFilterThreadFinished = true; });
//        connect(filterThread, &QThread::started, this, [&] () { isFilterThreadFinished = false; });
//        filterThread->start();
//    };

//    if (locked())
//    {

//        auto _wait = [this] ()
//        {
//            while (!locked());
//        };

//        QThread * waiter = QThread::create(_wait);

//        connect(waiter, &QThread::finished, this, workFilter);
//        waiter->start();
//    }

//    else
//    {
//        workFilter();
//    }
}

void SortingProxyModel::setLock(bool locked)
{
    locked_ = locked;
}

void SortingProxyModel::setLocked()
{
    locked_ = true;
}

void SortingProxyModel::setUnlocked()
{
    locked_ = false;
}

QVariant SortingProxyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    return sourceModel()->headerData(section, orientation, role);
}

bool SortingProxyModel::removeRows(int row, int count, const QModelIndex &parent)
{
    return false;
}

bool SortingProxyModel::locked()
{
    return locked_;
}

void SortingProxyModel::make_connects()
{
    PacketTableModel * src = qobject_cast<PacketTableModel*>(sourceModel());

    connect(src, &PacketTableModel::countChanged, this, [=] (const size_t size, const size_t capacity)
            {
        if (size == capacity) setLock(true);
        else setLock(false);
    });

}


bool SortingProxyModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    PacketTableModel * src = qobject_cast<PacketTableModel*>(sourceModel());
    const FrameInfo & fr = src->get(source_row);

    ProtocolHolder * node = fr.p_ref->First();

    mapFromSource(source_parent);

    if (enabled && !filterExpr.isEmpty())
    {
        QRegularExpression udp_matcher{QString("[uU][dD][pP]"), QRegularExpression::CaseInsensitiveOption};
        QRegularExpression tcp_matcher{QString("[tT][cC][pP]"), QRegularExpression::CaseInsensitiveOption};
        QRegularExpression dns_matcher{QString("[dD][nN][sS]"), QRegularExpression::CaseInsensitiveOption};
        QRegularExpression ip4_matcher{QString("[iI][pP](v)?(ersion)?4$"), QRegularExpression::CaseInsensitiveOption};
        QRegularExpression ip6_matcher{QString("[iI][pP](v)?(ersion)?6$"), QRegularExpression::CaseInsensitiveOption};
        QRegularExpression arp_matcher{QString("[aA][rR][pP]"), QRegularExpression::CaseInsensitiveOption};
        QRegularExpression icmp_matcher{QString("[iI][cC][mM][pP]"), QRegularExpression::CaseInsensitiveOption};
        QRegularExpression http_matcher{QString("[hH][tT][tT][pP]"), QRegularExpression::CaseInsensitiveOption};
        if (udp_matcher.match(filterExpr).hasMatch())
        {
            while (node)
            {
                if (node->type == CurrentUDP)
                {
                    filteredCount++;
                    return true;
                }
                node = node->next;
            }
            return false;
        }

        else if (tcp_matcher.match(filterExpr).hasMatch())
        {
            while (node)
            {
                if (node->type == CurrentTCP)
                {
                    filteredCount++;
                    return true;
                }
                node = node->next;
            }
            return false;
        }

        else if (dns_matcher.match(filterExpr).hasMatch())
        {
            while (node)
            {
                if (node->type == CurrentDNS)
                {
                    filteredCount++;
                    return true;
                }
                node = node->next;
            }
            return false;
        }

        else if (ip4_matcher.match(filterExpr).hasMatch())
        {
            while (node)
            {
                if (node->type == CurrentIPv4)
                {
                    filteredCount++;
                    return true;
                }
                node = node->next;
            }
            return false;
        }

        else if (ip6_matcher.match(filterExpr).hasMatch())
        {
            while (node)
            {
                if (node->type == CurrentIPv6)
                {
                    filteredCount++;
                    return true;
                }
                node = node->next;
            }
            return false;
        }

        else if (arp_matcher.match(filterExpr).hasMatch())
        {
            while (node)
            {
                if (node->type == CurrentARP)
                {
                    filteredCount++;
                    return true;
                }
                node = node->next;
            }
            return false;
        }

        else if (icmp_matcher.match(filterExpr).hasMatch())
        {
            while (node)
            {
                if (node->type == CurrentICMP)
                {
                    filteredCount++;
                    return true;
                }
                node = node->next;
            }
            return false;
        }
        else if (http_matcher.match(filterExpr).hasMatch())
        {
            return false;
        }

        return false;
    }


    filteredCount = sourceModel()->rowCount();
    return true;
}




