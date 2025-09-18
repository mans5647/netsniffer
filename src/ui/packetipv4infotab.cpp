#include "packetipv4infotab.h"
#include "ui_packetipv4infotab.h"

PacketIpV4InfoTab::PacketIpV4InfoTab(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketIpV4InfoTab)
{
    ui->setupUi(this);
}

PacketIpV4InfoTab::~PacketIpV4InfoTab()
{
    delete ui;
}
