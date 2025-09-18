#ifndef PACKETETHERNETINFOTAB_H
#define PACKETETHERNETINFOTAB_H

#include <QWidget>

namespace Ui {
class PacketEthernetInfoTab;
}

class PacketEthernetInfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketEthernetInfoTab(QWidget *parent = nullptr);
    ~PacketEthernetInfoTab();

private:
    Ui::PacketEthernetInfoTab *ui;
};

#endif // PACKETETHERNETINFOTAB_H
