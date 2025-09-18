#include "mainwindow.h"
#include "if_choose.h"
#include "ui_mainwindow.h"
#include "sortingproxymodel.h"
#include "metainfopanel.h"
#include "capturesettingsdialog.h"
#include "interfaceview.h"
#include "filesettingsview.h"
#include "interfaceitem.h"
#include "ui/packetgeneralinfotab.h"
#include "qhexview.h"
#include "model/buffer/qmemorybuffer.h"


#include <QPalette>
#include <QSplitter>
#include <QLineEdit>
#include <QFile>
#include <QFileInfo>

const char * MainWindow::ProgramName = "NetSniffer - анализатор пакетов";


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui_(new Ui::MainWindow)
{
    ui_->setupUi(this);

    QIcon icons[] = { QIcon("../icons/wifi.png"),
                     QIcon("../icons/stop.png"),
                     QIcon("../icons/setting.png"),
                     QIcon("../icons/diskette.png"),
                     QIcon("../icons/previous.png"),
                     QIcon("../icons/next.png") };

    ui_->StartCapture->setIcon(icons[0].pixmap(QSize(25, 25)));
    ui_->StopCapture->setIcon(icons[1].pixmap(QSize(25, 25)));
    ui_->Settings->setIcon(icons[2].pixmap(QSize(25, 25)));
    //ui_->Save_Dump->setIcon(icons[3].pixmap(QSize(25, 25)));


    ui_->OpenPcap->setIcon(QApplication::style()->standardIcon(QStyle::SP_DirIcon));
    ui_->PrevPacket->setIcon(icons[4].pixmap(QSize(100, 100)));
    ui_->NextPacket->setIcon(icons[5].pixmap(QSize(100, 100)));


    setWindowTitle(ProgramName);
    current_viewing_frame_ = nullptr;
    current_frame_ = nullptr;
    current_interface_ = nullptr;
    selected_tab_ = 0;
    tabs_alloc_total = 0;
    selectedPacket = -1;
    is_options_open_ = false;
    has_packets_ = false;
    locked_for_view_ = false;

    SetEnabledStopCapture(false);
    SetEnabledSaveCapture(false);
    SetEnabledStartCapture(false);
    SetEnabledIterButtons(false);


    QPalette p;
    p.setColor(QPalette::Window, QColor(Qt::GlobalColor::gray));
    ui_->splitter->setPalette(p);


    capture_manager_ = SessionManager::getInstance();


    QTableView * u_ref = ui_->PacketView;



    ui_->PacketView->setSortingEnabled(true);

    QHeaderView * horizontal = u_ref->horizontalHeader();
    horizontal->setMinimumSectionSize(100);
    horizontal->setMaximumSectionSize(2000);
    u_ref->setColumnWidth(COLUMN_NO, COL_NO_WIDTH * 2);
    u_ref->setColumnWidth(COLUMN_DIFF_TIME, COL_TIME_WIDTH * 5);
    u_ref->setColumnWidth(COLUMN_SRC, COL_SRC_WIDTH * 4);
    u_ref->setColumnWidth(COLUMN_DST, COL_DST_WIDTH * 4);
    u_ref->setColumnWidth(COLUMN_PROTO, COL_PROTO_WIDTH * 5);
    u_ref->setColumnWidth(COLUMN_LEN, COL_LEN_WIDTH * 3);
    u_ref->setColumnWidth(COLUMN_INFO, 900);


    u_ref->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);


    u_ref->setSelectionBehavior(QAbstractItemView::SelectRows);
    u_ref->setSelectionMode(QAbstractItemView::SingleSelection);
    u_ref->setEditTriggers(QAbstractItemView::NoEditTriggers);

    u_ref->setDragEnabled(false);
    u_ref->setDragDropMode(QAbstractItemView::NoDragDrop);

    u_ref->setGridStyle(Qt::PenStyle::NoPen);
    u_ref->setFrameShape(QFrame::NoFrame);


    ui_->ProtoDetailWidget->setMinimumSize(QSize(100, 100));
    ui_->ProtoDetailWidget->setMaximumSize(QSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX));
    ui_->ProtoDetailWidget->clear();



    tab_hex_layout = new QHBoxLayout(ui_->BottomFrame);

    delim = new QSplitter(Qt::Horizontal);

    // -- initialize hex view panel
    hex_view = new QHexView();
    hex_view->setDocument(QHexDocument::fromMemory<QMemoryBuffer>(current_hex_data_));
    // -- end


    cap_settings = new CaptureSettingsDialog();

    delim->addWidget(ui_->ProtoDetailWidget);
    delim->addWidget(hex_view);

    tab_hex_layout->addWidget(delim);


    _SetFont(QFont("Havletica", 10));

    ui_->PacketView->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    ui_->PacketView->verticalHeader()->setDefaultSectionSize(24);


    sorting_model_ = new SortingProxyModel(this);
    sorting_model_->setDynamicSortFilter(false);
    sorting_model_->setSourceModel(capture_manager_->GetPackets());
    sorting_model_->make_connects();
    ui_->PacketView->setModel(sorting_model_);
    ui_->PacketView->setSortingEnabled(true);


    meta_panel_ = new MetaInfoPanel();
    QVBoxLayout * mainGrid = qobject_cast<QVBoxLayout*>(ui_->MainGrid->layout());
    mainGrid->addWidget(meta_panel_);
    frame_row_selected_ = ui_->PacketView->selectionModel();
    connect(frame_row_selected_, &QItemSelectionModel::currentRowChanged, this, &MainWindow::ShowDetailed);
    connect(ui_->PacketView, SIGNAL(clicked(QModelIndex)), this, SLOT(ShowPacketDetailed(QModelIndex)));
    connect(ui_->ProtoDetailWidget, SIGNAL(currentChanged(int)), this, SLOT(SetTabIndex(int)));
    connect(ui_->filterExpr, &QLineEdit::returnPressed, this, &MainWindow::SetFilterAuto);
    connect(this, &MainWindow::FilterTriggered, sorting_model_, &SortingProxyModel::apply_filter);

    SetupInitialConnects();

}

void MainWindow::SetupInitialConnects()
{
    connect(ui_->Settings, &QPushButton::clicked, this, &MainWindow::ShowInterfaceWindow);
    connect(ui_->StopCapture, &QPushButton::clicked, capture_manager_, &SessionManager::StopCapture);
    connect(ui_->PrevPacket, &QPushButton::clicked, this, [=] () {} );
    connect(ui_->NextPacket, &QPushButton::clicked, this, &MainWindow::ToNext);

    connect(ui_->PacketView->model(), &QAbstractItemModel::rowsInserted, this,   [=] () { SetEnabledIterButtons(true); } );
    connect(ui_->PacketView->model(), &QAbstractItemModel::modelReset, this,     [=] () { SetEnabledIterButtons(false); } );

    PacketTableModel * currModel = qobject_cast<PacketTableModel*>(sorting_model_->sourceModel());
    connect(currModel, &PacketTableModel::countChanged, this, &MainWindow::CheckCurrentModelDataValidity);
    connect(capture_manager_, &SessionManager::CountUpdated, this,
            [this] ()
            {
                CalculateMetricsAuto();
            }
        );
    connect(sorting_model_, &SortingProxyModel::filterCountChanged, this, [this] (float count, float chunk)
            {
        meta_panel_->setChunkCount((const size_t)chunk);
        UpdatePercent(count, chunk);
    });


    connect(sorting_model_, &SortingProxyModel::filteringBegan, this, &MainWindow::DetachModel);
    connect(sorting_model_, &SortingProxyModel::filteringEnded, this, &MainWindow::AttachModel);


    connect(capture_manager_, &SessionManager::ModelClearStarted, this, &MainWindow::ResetAll);
    connect(capture_manager_, &SessionManager::ModelClearFinished, this, &MainWindow::SetupAll);

    connect(cap_settings->getTableView(), &InterfaceView::deviceSelected, this, &MainWindow::Startup);
    connect(capture_manager_, &SessionManager::StatusChanged, this, &MainWindow::SetCaptureStatus);

    connect(capture_manager_, &SessionManager::FileRemoved, this, &MainWindow::UpdateFileInfo);
    connect(capture_manager_, &SessionManager::FileSaved, this, &MainWindow::UpdateFileInfo);

    connect(ui_->OpenPcap, &QPushButton::clicked, this, &MainWindow::OpenForReadDump);
    connect(capture_manager_, &SessionManager::ModelPopulateStarted, this, &MainWindow::ResetAll);
    connect(capture_manager_, &SessionManager::ModelPopulateFinished, this, &MainWindow::SetupAll);

    connect(capture_manager_, &SessionManager::FileNameFetched, this, [=] (const QString & fname)
    {
        QFile __dumpInfo{fname};
        QFileInfo fi{fname};
        file_path_ = fname;
        setWindowTitle(fi.fileName());
        meta_panel_->addFileName(fi.fileName());
    });
}


MainWindow::MainWindowPtrImpl MainWindow::GetUI() { return ui_; }


void MainWindow::SetOpenedState(bool opened)
{
    is_options_open_ = opened;
}


void MainWindow::ShowInterfaceWindow()
{
    if (is_options_open_) return;
    cap_settings->show();
}

void MainWindow::SetEnabledStopCapture(bool flag)
{
    ui_->StopCapture->setEnabled(flag);
}

void MainWindow::SetEnabledSaveCapture(bool flag)
{

}

void MainWindow::SetEnabledStartCapture(bool flag)
{
    ui_->StartCapture->setEnabled(flag);
}

void MainWindow::SetEnabledCaptureOptions(bool flag)
{
    ui_->Settings->setEnabled(flag);
}

void MainWindow::SetEnabledIterButtons(bool flag)
{
    ui_->NextPacket->setEnabled(flag);
    ui_->PrevPacket->setEnabled(flag);
}

void MainWindow::SetEnabledOpenPcapDump(bool flag)
{
    ui_->OpenPcap->setEnabled(flag);
}

void MainWindow::ShowPacketDetailed(const QModelIndex & index)
{

    QModelIndex mappedIndex = sorting_model_->mapToSource(index);

    if (!mappedIndex.isValid()) return;

    int row = mappedIndex.row();
    PacketTableModel * packets = qobject_cast<PacketTableModel*>(capture_manager_->GetPackets());


    // if (IsLocked())
    // {
    //     if (tabsAllocated > 0)
    //     {
    //         _FreeAllTabs();
    //     }
    //     hex_view->hexDocument()->reset();
    // }

    // else
    // {

    //     auto List = packets->get_list_ptr();

    //     auto begin = List->begin();
    //     auto end = List->end();

    //     if (begin == end) return;

    //     const FrameInfo & value = packets->get(row);

    //     delete current_frame_;
    //     current_frame_ = new FrameInfo(value);

    //     if (tabs_alloc_total > 0)
    //     {
    //         _FreeAllTabs();
    //     }


    //     tabs = new GenericTab*[TAB_MAX];

    //     tabs[GNINFO_INDEX] = new GenericTab(TabType::General, current_frame_, nullptr);
    //     tabs[ETH_INDEX] = new GenericTab(TabType::Ethernet, current_frame_, nullptr);

    //     tabs[GNINFO_INDEX]->getTab()->pinfo->commit();
    //     tabs[ETH_INDEX]->getTab()->eth->commit();


    //     ui_->ProtoDetailWidget->addTab(tabs[GNINFO_INDEX]->getMainWidget(),  GENERAL_TAB_NAME_RU);
    //     ui_->ProtoDetailWidget->addTab(tabs[ETH_INDEX]->getMainWidget(),     ETHERNET_TAB_RUS);

    //     tabs_alloc_total += 2;

    //     auto __getProtocolName = [](TabType type) -> QString
    //     {
    //         switch (type)
    //         {
    //         case TabType::V4: return  tr(IPv4_TAB_RU);
    //         case TabType::ARP: return tr("Протокол определения адреса (ARP)");
    //         case TabType::TCP: return tr("Протокол управления передачей (TCP)");
    //         case TabType::UDP: return tr("Протокол датаграмм клиента (UDP)");
    //         case TabType::ICMP: return tr("Протокол управления интернет сообщениями (ICMP)");
    //         case TabType::DNS: return tr("Система доменных имен (DNS)");
    //         }
    //         return tr("Unknown");
    //     };




    //     ProtocolHolder * proto_node = current_frame_->p_ref->First();

    //     int tab_index = 2;
    //     for (; proto_node; proto_node = proto_node->next)
    //     {
    //         bool is_valid = false;
    //         BaseTabWidget * basic_tab = nullptr;
    //         ParentArea * mwidget = nullptr;
    //         TabType type;
    //         switch (proto_node->type)
    //         {
    //         case CurrentIPv4:
    //         {
    //             tabs[tab_index] = new GenericTab(TabType::V4, &value, proto_node);
    //             basic_tab = tabs[tab_index]->getTab()->v4;
    //             mwidget = tabs[tab_index]->getMainWidget();
    //             is_valid = true;
    //             tabsAllocated++;
    //             type = TabType::V4;
    //             break;
    //         }
    //         case CurrentARP:
    //         {
    //             tabs[tab_index] = new GenericTab(TabType::ARP, &value, proto_node);
    //             basic_tab = tabs[tab_index]->getTab()->_arp;
    //             mwidget = tabs[tab_index]->getMainWidget();
    //             is_valid = true;
    //             tabsAllocated++;
    //             type = TabType::ARP;
    //             break;
    //         }
    //         case CurrentTCP:
    //         {
    //             tabs[tab_index] = new GenericTab(TabType::TCP, &value, proto_node);
    //             basic_tab = tabs[tab_index]->getTab()->_tcp;
    //             mwidget = tabs[tab_index]->getMainWidget();
    //             is_valid = true;
    //             tabsAllocated++;
    //             type = TabType::TCP;
    //             break;
    //         }
    //         case CurrentUDP:
    //         {
    //             tabs[tab_index] = new GenericTab(TabType::UDP, &value, proto_node);
    //             basic_tab = tabs[tab_index]->getTab()->_udp;
    //             mwidget = tabs[tab_index]->getMainWidget();
    //             is_valid = true;
    //             tabsAllocated++;
    //             type = TabType::UDP;
    //             break;
    //         }
    //         case CurrentICMP:
    //         {
    //             tabs[tab_index] = new GenericTab(TabType::ICMP, &value, proto_node);
    //             basic_tab = tabs[tab_index]->getTab()->_icmp;
    //             mwidget = tabs[tab_index]->getMainWidget();
    //             is_valid = true;
    //             tabsAllocated++;
    //             type = TabType::ICMP;
    //             break;
    //         }
    //         case CurrentDNS:
    //         {
    //             tabs[tab_index] = new GenericTab(TabType::DNS, &value, proto_node);
    //             basic_tab = tabs[tab_index]->getTab()->_dns;
    //             mwidget = tabs[tab_index]->getMainWidget();
    //             is_valid = true;
    //             tabsAllocated++;
    //             type = TabType::DNS;
    //             break;
    //         }

    //         default: is_valid = false;

    //         }

    //         if (is_valid)
    //         {
    //             basic_tab->commit();
    //             ui_->ProtoDetailWidget->addTab(mwidget, __getProtocolName(type));
    //             tab_index++;
    //         }

    //     }

    //     // insert data to HEX VIEW!
    //     hex_view->hexDocument()->insert(0, current_frame_->copy);
    // }

}

void MainWindow::ShowDetailed(const QModelIndex & current, const QModelIndex & previous)
{
    ShowPacketDetailed(current);
}

void MainWindow::SetTabIndex(int index)
{
    selected_tab_ = index;
}

void MainWindow::SetFilterAuto()
{
    QString expr = ui_->filterExpr->text();
    if (expr.isEmpty())
    {
        emit FilterTriggered(expr, false);
    }
    else
    {
        emit FilterTriggered(expr, true);

    }

    if (tabs_alloc_total)
    {
        _FreeAllTabs();
    }

    hex_view->hexDocument()->reset();
}

void MainWindow::ToNext()
{

    auto onViewModel = ui_->PacketView->model();
    if (onViewModel)
    {
        QItemSelectionModel * selectionModel = ui_->PacketView->selectionModel();
        QModelIndex current = selectionModel->currentIndex();
        QModelIndex next = onViewModel->index(current.row() + 1, current.column());

        selectionModel->setCurrentIndex(next, QItemSelectionModel::ToggleCurrent);
        ShowPacketDetailed(next);
    }
}

void MainWindow::ToPrevious()
{
    auto onViewModel = ui_->PacketView->model();
    if (onViewModel)
    {
        QItemSelectionModel * selectionModel = ui_->PacketView->selectionModel();
        QModelIndex current = selectionModel->currentIndex();
        QModelIndex prev = onViewModel->index(current.row() - 1, current.column());

        selectionModel->setCurrentIndex(prev, QItemSelectionModel::ToggleCurrent);
        ShowPacketDetailed(prev);
    }
}


void MainWindow::ResetHexPanel()
{
    GetHexPanel()->hexDocument()->reset();
}

void MainWindow::ResetProtoViewPanel()
{
    // if (tabsAllocated > 0)
    // {
    //     FreeAllTabs();
    // }
}

void MainWindow::ReconnectSelectionSignals()
{
    QItemSelectionModel * selectionModel = ui_->PacketView->selectionModel();
    connect(selectionModel, &QItemSelectionModel::currentRowChanged, this, &MainWindow::ShowDetailed);
    connect(ui_->PacketView, &QTableView::clicked, this, &MainWindow::ShowPacketDetailed);
}

void MainWindow::SortPackets(int index, Qt::SortOrder order)
{

}

void MainWindow::UpdatePacketCountAuto()
{
    auto model = sorting_model_->sourceModel();
    size_t count = 0;

    if (model)
    {
        count = model->rowCount();
    }

    meta_panel_->setTotalCount(count);
}

void MainWindow::UpdateChunkCountAuto()
{
    auto model = ui_->PacketView->model();
    size_t count = 0;

    if (model)
    {
        count = model->rowCount();
    }

    meta_panel_->setChunkCount(count);
}

void MainWindow::CalculateMetricsAuto()
{
    UpdatePacketCountAuto();
    UpdateChunkCountAuto();
    auto counts_ = _GetCurrentCounts();
    UpdatePercent(static_cast<float>(counts_.first), static_cast<float>(counts_.second));

    QFile cpt_file{};
    cpt_file.setFileName(file_path_);
    cpt_file.open(QIODevice::ReadOnly);
    meta_panel_->updateFileInfo(cpt_file);
}

void MainWindow::UpdatePercent(float total, float chunk)
{
    const float percent = PacketTableModel::calculatePercent(total, chunk);
    meta_panel_->setPercentCount(percent);
}

void MainWindow::CheckCurrentModelDataValidity(const size_t size, const size_t cap)
{
    if (size == cap)
    {
        locked_for_view_ = true;
    }
    else
    {
        locked_for_view_ = false;
    }
}

void MainWindow::DetachModel()
{
    ui_->PacketView->setModel(nullptr);
    //hex_view->reset();
    hex_view->hexDocument()->reset();
    //if (tabs_alloc_total) FreeAllTabs();
}

void MainWindow::AttachModel()
{
    ui_->PacketView->setModel(sorting_model_);
    ReconnectSelectionSignals();
    ui_->PacketView->setSortingEnabled(true);
}

void MainWindow::ResetAll()
{
    DetachModel();
    meta_panel_->setTotalCount(0);
    meta_panel_->setChunkCount(0);
    meta_panel_->setPercentCount(0.0f);

    meta_panel_->addWarning("Resetting model ...");
}

void MainWindow::SetupAll()
{
    AttachModel();
    CalculateMetricsAuto();
    meta_panel_->removeWarning();
}

SortingProxyModel *MainWindow::GetSortingModel()
{
    return sorting_model_;
}

QHexView *MainWindow::GetHexPanel()
{
    return hex_view;
}

void MainWindow::_SetFont(const QFont &_font)
{
    ui_->PacketView->setFont(_font);
    ui_->PacketView->horizontalHeader()->setFont(_font);
}

void MainWindow::_FreeAllTabs() noexcept
{
    // for (unsigned i = 0; i < tabsAllocated; i++) delete tabs[i];
    // tabsAllocated = 0;
    // ui_->ProtoDetailWidget->clear();
}

bool MainWindow::IsLocked() const
{
    return locked_for_view_;
}

QPair<size_t, size_t> MainWindow::_GetCurrentCounts()
{
    auto srcModel = sorting_model_->sourceModel();
    auto inViewModel = ui_->PacketView->model();

    size_t CountInTotal = 0, CountInTable = 0;
    if (srcModel && inViewModel)
    {
        CountInTotal = srcModel->rowCount();
        CountInTable = inViewModel->rowCount();
    }

    return QPair<size_t, size_t>(CountInTotal, CountInTable);
}

void MainWindow::closeEvent(QCloseEvent *event)
{

}



void MainWindow::focusOutEvent(QFocusEvent *event)
{

}

void MainWindow::mousePressEvent(QMouseEvent *event)
{

}

void MainWindow::leaveEvent(QEvent *event)
{

}

void MainWindow::changeEvent(QEvent *event)
{

}


MainWindow::~MainWindow()
{
    delete ui_;
}

void MainWindow::OpenForReadDump()
{
    capture_manager_->LoadCaptureFile();
}

void MainWindow::UpdateFileInfo()
{
    cap_settings->prepareFile();
    file_name_ = cap_settings->getFilename();
    file_path_ = cap_settings->getFullPath();

    QFile cpt_file;
    cpt_file.setFileName(file_path_);
    cpt_file.open(QIODevice::ReadOnly);
    meta_panel_->updateFileInfo(cpt_file);
}

void MainWindow::CreateMessageBox(const QString &title, const QString &description, const QIcon &ico)
{
    QMessageBox(QMessageBox::Icon::Information, title, description).exec();
}

void MainWindow::Startup()
{
    cap_settings->hide();

    const InterfaceItem * item = cap_settings->getTableView()->getSelectedItem();
    SetInterface(item);
    capture_manager_->SetInterface(item);
    cap_settings->prepareFile();

    file_name_ = cap_settings->getFilename();
    file_path_ = cap_settings->getFullPath();

    capture_manager_->SetDumpWritePath(file_path_);
    meta_panel_->addFileName(file_name_);
    capture_manager_->StartCapture();
}

void MainWindow::SetInterface(const InterfaceItem *_interface)
{
    current_interface_ = _interface;
}

void MainWindow::SetCaptureStatus(SessionManager::CaptureStatus status)
{
    QString statusTitle;
    if (status == SessionManager::CaptureStatus::Started)
    {
        auto link_type = pcap_datalink(capture_manager_->GetRawCaptureHandle());
        statusTitle = "Проводится захват";

        if (current_interface_)
        {
            statusTitle += tr(" Тип устройства: [ ");
            switch (current_interface_->GetType())
            {
            case DeviceType::Unknown: statusTitle += tr("Неизвестное устройство"); break;
            case DeviceType::Ethernet: statusTitle += tr("Ethernet"); break;
            case DeviceType::Wireless: statusTitle += tr("Беспроводное"); break;
            case DeviceType::Loopback: statusTitle += tr("Loopback"); break;
            case DeviceType::Other: statusTitle+= tr("Другое"); break;
            }

            statusTitle += QString(" ] имя: %1").arg(current_interface_->GetFriendlyName());
            meta_panel_->setDeviceName(current_interface_->GetFriendlyName());
        }
        SetEnabledCaptureOptions(false);
        SetEnabledStopCapture(true);
        SetEnabledOpenPcapDump(false);
    }
    else
    {
        locked_for_view_ = false;
        sorting_model_->setLock(false);
        statusTitle = tr("Захват остановлен");
        SetEnabledCaptureOptions(true);
        SetEnabledStopCapture(false);
        SetEnabledOpenPcapDump(true);
    }



    setWindowTitle(statusTitle);
}

