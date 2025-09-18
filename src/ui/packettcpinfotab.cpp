#include "packettcpinfotab.h"
#include "ui_packettcpinfotab.h"

PacketTcpInfoTab::PacketTcpInfoTab(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketTcpInfoTab)
{
    ui->setupUi(this);
}

PacketTcpInfoTab::~PacketTcpInfoTab()
{
    delete ui;
}
