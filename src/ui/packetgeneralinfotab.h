#ifndef PACKETGENERALINFOTAB_H
#define PACKETGENERALINFOTAB_H

#include <QWidget>
#include "proto_list.h"

namespace Ui {
class PacketGeneralInfoTab;
}

class PacketGeneralInfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketGeneralInfoTab(
            QWidget *parent = nullptr);
    ~PacketGeneralInfoTab();

private:
    Ui::PacketGeneralInfoTab *ui;
};

#endif // PACKETGENERALINFOTAB_H
