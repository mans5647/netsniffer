#include "if_choose.h"
#include "ui_mainwindow.h"
#include "if_loader.h"
#include "helpers.h"
#include "sessionmanager.h"
#include "interfacerow.h"

if_choose::if_choose(MainWindow * window,QWidget *parent) :
    QWidget(parent), std::vector<pcap_if_t*>(),
    ui(new Ui::if_choose)
{
    ui->setupUi(this);
    mWindowRef = window;
    CurrentRow = -1;
    LastRow = -1;
    SelectionCount = 0;
    DeviceStarted = false;
    CaptureStarted = false;
    RegisterSignals();

    SetButtonStartEnabled(false);
}

void if_choose::SetHandler(state_handler cb)
{
    callback = cb;
}

void if_choose::BeginLoading()
{
    LoadInterfaces(this,errbuf, nullptr,&devices_);
}

void if_choose::RegisterSignals()
{
    setconn(ui->close_btn, SIGNAL(clicked(bool)), this, SLOT(CloseSlot()))
    setconn(ui->start_cpt_btn, SIGNAL(clicked(bool)), this, SLOT(StartCaptureSlot()));
    setconn(ui->interface_list, SIGNAL(cellActivated(int,int)), this, SLOT(SetCurrentRow(int,int)))
    setconn(this, SIGNAL(DeviceSelected(bool)), mWindowRef, SLOT(SetEnabledStopCapture(bool)))
    setconn(this, SIGNAL(DisableOptsButton(bool)), mWindowRef, SLOT(SetEnabledCaptureOptions(bool)))
}

void if_choose::showEvent(QShowEvent * event)
{
    (mWindowRef->*callback)(true);
}

void if_choose::closeEvent(QCloseEvent *p)
{
    (mWindowRef->*callback)(false);
    clear();
    ui->interface_list->clear();
    delete this;
}

void if_choose::StartCaptureSlot()
{

}

void if_choose::CloseSlot()
{
    close();
}

void if_choose::SetCurrentRow(int row, int column)
{
    if (SelectionCount > 0)
    {
        QBrush * NoColor = new QBrush;
        NoColor->setStyle(Qt::BrushStyle::NoBrush);
        NoColor->setColor(Qt::GlobalColor::white);

        for (auto col = 0; col < MAX_IFCOL; col++)
        {
            auto item = ui->interface_list->item(LastRow, col);
            item->setBackground(*NoColor);
        }
        delete NoColor;
    }

    QList<QTableWidgetItem*> selected_row = ui->interface_list->selectedItems();

    QBrush * color = new QBrush;
    color->setStyle(Qt::BrushStyle::SolidPattern);
    color->setColor(Qt::GlobalColor::green);
    for (auto && item : selected_row)
    {
        item->setBackground(*color);
    }

    CurrentRow = row;
    LastRow = CurrentRow;
    SelectionCount++;

    SetButtonStartEnabled(true);
    delete color;
}

void if_choose::SetButtonStartEnabled(bool flag)
{
    ui->start_cpt_btn->setEnabled(flag);
}

if_choose::~if_choose()
{
    delete ui;
}
