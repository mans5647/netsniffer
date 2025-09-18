#ifndef PACKETDNSINFOTAB_H
#define PACKETDNSINFOTAB_H

#include <QWidget>

namespace Ui {
class PacketDnsInfoTab;
}

class PacketDnsInfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketDnsInfoTab(QWidget *parent = nullptr);
    ~PacketDnsInfoTab();

private:
    Ui::PacketDnsInfoTab *ui;
};

#endif // PACKETDNSINFOTAB_H
