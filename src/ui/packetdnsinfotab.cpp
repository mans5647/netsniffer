#include "packetdnsinfotab.h"
#include "ui_packetdnsinfotab.h"

PacketDnsInfoTab::PacketDnsInfoTab(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketDnsInfoTab)
{
    ui->setupUi(this);
}

PacketDnsInfoTab::~PacketDnsInfoTab()
{
    delete ui;
}
