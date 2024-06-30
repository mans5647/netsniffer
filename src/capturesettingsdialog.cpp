#include "capturesettingsdialog.h"
#include "interfaceview.h"
#include "filesettingsview.h"
#include "interfacemodel.h"
#include <QTabWidget>
#include <QVBoxLayout>
#include <QSize>
#include <QPushButton>
#include <QDateTime>

CaptureSettingsDialog::CaptureSettingsDialog()
{
    setWindowTitle(widgetName);
    mLayout = new QVBoxLayout;
    action_box_layout = new QHBoxLayout;
    tabs = new QTabWidget;
    device_table = new InterfaceView();
    file_settings = new FileSettingsView();
    if_area = new InterfaceArea();
    file_area = new FileArea();

    if_area->addWidgetToLayout(device_table);
    file_area->addWidgetToLayout(file_settings);
    if_area->resize(QSize(device_table->width(), device_table->height()));

    tabs->addTab(if_area, tab_if_name);
    tabs->addTab(file_area, tab_file_settings_name);
    mLayout->addWidget(tabs);


    action_box = new QGroupBox(QObject::tr("Действия"));

    reload_ifaces_btn = new QPushButton;
    reload_ifaces_btn->setText(QObject::tr("Перезагрузить интерфейсы"));
    delimeter = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Maximum);
    apply = new QPushButton;
    apply->setText(QObject::tr("Применить"));
    cancel = new QPushButton;
    cancel->setText(QObject::tr("Закрыть"));

    action_box_layout->addWidget(reload_ifaces_btn);
    action_box_layout->addSpacerItem(delimeter);
    action_box_layout->addWidget(apply);
    action_box_layout->addWidget(cancel);

    action_box->setLayout(action_box_layout);

    mLayout->addWidget(action_box);
    setLayout(mLayout);

    int persistentW = if_area->width() + (if_area->width() / 2);
    int persistentH = if_area->height();
    setFixedSize(QSize(persistentW, persistentH));

    connect(reload_ifaces_btn, &QPushButton::clicked, device_table->getModel(), &InterfaceModel::ReloadAllDevices);
    connect(apply, &QPushButton::clicked, device_table, &InterfaceView::notifyIfSelected);
    connect(apply, &QPushButton::clicked, this, &CaptureSettingsDialog::prepareFile);
    connect(cancel, &QPushButton::clicked, this, &CaptureSettingsDialog::hide);
}

CaptureSettingsDialog::~CaptureSettingsDialog()
{
    delete tabs;
}

InterfaceView *CaptureSettingsDialog::getTableView()
{
    return device_table;
}

FileSettingsView *CaptureSettingsDialog::getFileSettings()
{
    return file_settings;
}

QString CaptureSettingsDialog::getFullPath() const
{
    return file_settings->getLocation() + "/" + file_settings->getFilename();
}

QString CaptureSettingsDialog::getLocation() const
{
    return file_settings->getLocation();
}

QString CaptureSettingsDialog::getFilename() const
{
    return file_settings->getFilename();
}

void CaptureSettingsDialog::prepareFile()
{
    FileNameMode mode = file_settings->getMode();
    if (mode == Special)
    {
        auto str_time = QDateTime::currentDateTime().toString("dd-MM-yyyy");
        auto iface = device_table->getSelectedItem();
        auto iface_name = iface ? iface->getFriendlyName() : QByteArray("Unkwown");
        file_settings->SetDefaultName(str_time, iface_name);
    }
    else if (mode == Custom)
    {
        if (file_settings->getFilename().isEmpty())
        {
            auto str_time = QDateTime::currentDateTime().toString("dd-MM-yyyy");
            auto iface = device_table->getSelectedItem();
            auto iface_name = iface ? iface->getFriendlyName() : QByteArray("Unkwown");
            file_settings->SetDefaultName(str_time, iface_name);
        }
    }


}

CaptureSettingsDialog::InterfaceArea::InterfaceArea(QWidget * parent) : BaseArea(parent)
{

}

CaptureSettingsDialog::BaseArea::BaseArea(QWidget *parent)
{
    areaLayout = new QVBoxLayout;
    setFrameShape(QFrame::NoFrame);
    setLayout(areaLayout);
}

void CaptureSettingsDialog::BaseArea::addWidgetToLayout(QWidget *widget)
{
    areaLayout->addWidget(widget);
}

CaptureSettingsDialog::FileArea::FileArea(QWidget *parent)
{

}
