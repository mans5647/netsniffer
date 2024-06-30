#include "metainfopanel.h"

MetaInfoPanel::MetaInfoPanel()
{
    m_layout = new QHBoxLayout;
    totalPackets = new QLabel;
    chunkPackets = new QLabel;
    notifyLabel = new QLabel;
    totalPacketsPercent = new QLabel;
    deviceName = new QLabel;
    fileName = new QLabel;
    fileSize = new QLabel;
    space = new QSpacerItem(40, 20, QSizePolicy::Expanding);


    m_layout->addWidget(totalPackets);
    m_layout->addWidget(chunkPackets);
    m_layout->addWidget(totalPacketsPercent);
    m_layout->addWidget(deviceName);
    m_layout->addWidget(fileName);
    m_layout->addWidget(fileSize);
    m_layout->addSpacerItem(space);

    setTotalCount(0);
    setChunkCount(0);
    setPercentCount(0.0f);
    setDeviceName("Не выбрано");
    addFileName(QString());
    updateFileInfo(QFile());

    setLayout(m_layout);

}

void MetaInfoPanel::setTotalCount(const size_t count)
{
    totalPackets->setText(QString("Всего: %1").arg(count));
}

void MetaInfoPanel::setChunkCount(const size_t count)
{
    chunkPackets->setText(QString("Показываются: %1").arg(count));
}

void MetaInfoPanel::setPercentCount(const float count)
{
    totalPacketsPercent->setText(QString("(%1 %)").arg(std::isnan(count) ? 0 : count));
}

void MetaInfoPanel::setDeviceName(const QString &name)
{
    deviceName->setText(QString("Устройство: %1").arg(name));
}

void MetaInfoPanel::addWarning(const QString &text)
{
    notifyLabel->setText(text);
    m_layout->addWidget(notifyLabel);
}

void MetaInfoPanel::addFileName(const QString &fname)
{
    fileName->setText(QString("Файл: %1").arg(fname.isEmpty() ? "<имя отсутствует>" : fname));
}

void MetaInfoPanel::updateFileInfo(const QFile & file)
{
    fileSize->setText(QString("%1").arg(formatBytes(file.size())));
}



void MetaInfoPanel::removeWarning()
{
    notifyLabel->hide();
}

QString MetaInfoPanel::formatBytes(size_t bytes)
{
    size_t divisor;
    QString suffix;
    if(bytes < 1024) return QString("%1 байт").arg(bytes);

    if(bytes < 1024*1024)               { divisor = 1024;           suffix = "кб."; }
    else if(bytes < 1024*1024*1024)     { divisor = 1024*1024;      suffix = "мб."; }
    else                                { divisor = 1024*1024*1024; suffix = "гб."; }

    return QString("%1 %2").arg((float)bytes / divisor).arg(suffix);
}
