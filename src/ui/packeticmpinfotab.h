#ifndef PACKETICMPINFOTAB_H
#define PACKETICMPINFOTAB_H

#include <QWidget>

namespace Ui {
class PacketIcmpInfoTab;
}

class PacketIcmpInfoTab : public QWidget
{
    Q_OBJECT

public:
    explicit PacketIcmpInfoTab(QWidget *parent = nullptr);
    ~PacketIcmpInfoTab();

private:
    Ui::PacketIcmpInfoTab *ui;
};

#endif // PACKETICMPINFOTAB_H
