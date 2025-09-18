#ifndef PACKETTCPINFOTAB_H
#define PACKETTCPINFOTAB_H

#include <QWidget>

namespace Ui {
class PacketTcpInfoTab;
}

class PacketTcpInfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketTcpInfoTab(QWidget *parent = nullptr);
    ~PacketTcpInfoTab();

private:
    Ui::PacketTcpInfoTab *ui;
};

#endif // PACKETTCPINFOTAB_H
