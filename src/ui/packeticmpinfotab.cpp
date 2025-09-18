#include "packeticmpinfotab.h"
#include "ui_packeticmpinfotab.h"

PacketIcmpInfoTab::PacketIcmpInfoTab(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketIcmpInfoTab)
{
    ui->setupUi(this);
}

PacketIcmpInfoTab::~PacketIcmpInfoTab()
{
    delete ui;
}
