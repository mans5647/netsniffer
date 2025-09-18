#ifndef PACKETUDPINFOTAB_H
#define PACKETUDPINFOTAB_H

#include <QWidget>

namespace Ui {
class PacketUdpInfoTab;
}

class PacketUdpInfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketUdpInfoTab(QWidget *parent = nullptr);
    ~PacketUdpInfoTab();

private:
    Ui::PacketUdpInfoTab *ui;
};

#endif // PACKETUDPINFOTAB_H
