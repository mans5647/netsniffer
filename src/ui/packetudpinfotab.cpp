#include "packetudpinfotab.h"
#include "ui_packetudpinfotab.h"

PacketUdpInfoTab::PacketUdpInfoTab(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketUdpInfoTab)
{
    ui->setupUi(this);
}

PacketUdpInfoTab::~PacketUdpInfoTab()
{
    delete ui;
}
