#ifndef PACKETARPINFOTAB_H
#define PACKETARPINFOTAB_H

#include <QWidget>

namespace Ui {
class PacketArpInfoTab;
}

class PacketArpInfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketArpInfoTab(QWidget *parent = nullptr);
    ~PacketArpInfoTab();

private:
    Ui::PacketArpInfoTab *ui;
};

#endif // PACKETARPINFOTAB_H
