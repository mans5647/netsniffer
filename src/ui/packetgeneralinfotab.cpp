#include "packetgeneralinfotab.h"
#include "ui_packetgeneralinfotab.h"
#include <QDateTime>


PacketGeneralInfoTab::PacketGeneralInfoTab(
        QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketGeneralInfoTab)
{
    ui->setupUi(this);

    // ui->frameId->setText(QString::number(frame.f_num));
    // ui->frameArrivalUnix->setText(QString::number(frame.recv_time));
    // ui->frameArrivalLocal->setText(QDateTime::fromSecsSinceEpoch(
    //                                    frame.recv_time
    //                                    ).toLocalTime().toString());
    // ui->frameArrivalUtc->setText(QDateTime::fromSecsSinceEpoch(
    //                                 frame.recv_time)
    //                                 .toUTC().toString());

    // ui->frameProtos->setText(frameProtosAsString(frame));
    // ui->frameSizeActual->setText(QString("%d байт").arg(frame.total_length));
    // ui->frameSizeCapture->setText(QString("%d байт").arg(frame.cap_len));
}

PacketGeneralInfoTab::~PacketGeneralInfoTab()
{
    delete ui;
}
