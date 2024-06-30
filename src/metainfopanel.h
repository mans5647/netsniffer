#ifndef METAINFOPANEL_H
#define METAINFOPANEL_H

#include <QWidget>
#include <QObject>
#include <QHBoxLayout>
#include <QLabel>
#include <QString>
#include <QFile>

class MetaInfoPanel : public QWidget
{
    Q_OBJECT
public:
    MetaInfoPanel();
public slots:
    void setTotalCount(const size_t);
    void setChunkCount(const size_t);
    void setPercentCount(const float);
    void setDeviceName(const QString & name);
    void addWarning(const QString & text);
    void addFileName(const QString & fname);
    void updateFileInfo(const QFile & file);
    void removeWarning();

    QString formatBytes(size_t bytes);

private:

    QHBoxLayout * m_layout;
    QLabel * totalPackets;
    QLabel * chunkPackets;
    QLabel * totalPacketsPercent;
    QLabel * notifyLabel;
    QLabel * deviceName;
    QLabel * fileName;
    QLabel * fileSize;
    QSpacerItem * space;
};

#endif // METAINFOPANEL_H
