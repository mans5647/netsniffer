#ifndef PACKETIPV4INFOTAB_H
#define PACKETIPV4INFOTAB_H

#include <QWidget>

namespace Ui {
class PacketIpV4InfoTab;
}

class PacketIpV4InfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketIpV4InfoTab(QWidget *parent = nullptr);
    ~PacketIpV4InfoTab();

private:
    Ui::PacketIpV4InfoTab *ui;
};

#endif // PACKETIPV4INFOTAB_H
