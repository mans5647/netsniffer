#include "packetarpinfotab.h"
#include "ui_packetarpinfotab.h"

PacketArpInfoTab::PacketArpInfoTab(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketArpInfoTab)
{
    ui->setupUi(this);
}

PacketArpInfoTab::~PacketArpInfoTab()
{
    delete ui;
}
