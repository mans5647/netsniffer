#include "packetethernetinfotab.h"
#include "ui_packetethernetinfotab.h"

PacketEthernetInfoTab::PacketEthernetInfoTab(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketEthernetInfoTab)
{
    ui->setupUi(this);
}

PacketEthernetInfoTab::~PacketEthernetInfoTab()
{
    delete ui;
}
