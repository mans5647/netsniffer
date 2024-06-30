#include "mainwindow.h"
#include "if_choose.h"
#include "ui_mainwindow.h"
#include "sortingproxymodel.h"
#include "metainfopanel.h"
#include "myhexview.h"
#include <QPalette>
#include <QSplitter>
#include <QLineEdit>
#include <QFile>
#include <QFileInfo>
#include "capturesettingsdialog.h"
#include "interfaceview.h"
#include "filesettingsview.h"
#include "interfaceitem.h"
#include "llhttp.h"

const char * MainWindow::program_name = "NetSniffer - анализатор пакетов";

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QIcon icons[] = { QIcon("../icons/wifi.png"),
                     QIcon("../icons/stop.png"),
                     QIcon("../icons/setting.png"),
                     QIcon("../icons/diskette.png"),
                     QIcon("../icons/previous.png"),
                     QIcon("../icons/next.png") };



    ui->StartCapture->setIcon(icons[0].pixmap(QSize(25, 25)));
    ui->StopCapture->setIcon(icons[1].pixmap(QSize(25, 25)));
    ui->Settings->setIcon(icons[2].pixmap(QSize(25, 25)));
    //ui->Save_Dump->setIcon(icons[3].pixmap(QSize(25, 25)));


    ui->OpenPcap->setIcon(QApplication::style()->standardIcon(QStyle::SP_DirIcon));
    ui->PrevPacket->setIcon(icons[4].pixmap(QSize(100, 100)));
    ui->NextPacket->setIcon(icons[5].pixmap(QSize(100, 100)));


    setWindowTitle(program_name);
    currentViewingFrame = nullptr;
    currentFrame = nullptr;
    currentInterface = nullptr;
    selectedTab = 0;
    tabsAllocated = 0;
    selectedPacket = -1;
    is_options_widget_opened = false;
    has_packets = false;
    locked_for_view = false;

    SetEnabledStopCapture(false);
    SetEnabledSaveCapture(false);
    SetEnabledStartCapture(false);
    SetEnabledIterButtons(false);


    QPalette p;
    p.setColor(QPalette::Window, QColor(Qt::GlobalColor::gray));
    ui->splitter->setPalette(p);


    captureManager = SessionManager::getInstance();


    QTableView * u_ref = ui->PacketView;



    ui->PacketView->setSortingEnabled(true);

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


    ui->ProtoDetailWidget->setMinimumSize(QSize(100, 100));
    ui->ProtoDetailWidget->setMaximumSize(QSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX));
    ui->ProtoDetailWidget->clear();



    tab_hex_layout = new QHBoxLayout(ui->BottomFrame);

    delim = new QSplitter(Qt::Horizontal);

    hex_view = new MyHexView(QByteArray());
    CaptureSettings = new CaptureSettingsDialog();

    delim->addWidget(ui->ProtoDetailWidget);
    delim->addWidget(hex_view);

    tab_hex_layout->addWidget(delim);

    auto _font = QFont("Havletica", 10);
    _font.setStyleHint(QFont::Monospace);
    SetFont(_font);

    ui->PacketView->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    ui->PacketView->verticalHeader()->setDefaultSectionSize(24);


    sortingModel = new SortingProxyModel(this);
    sortingModel->setDynamicSortFilter(false);
    sortingModel->setSourceModel(captureManager->getModel());
    sortingModel->make_connects();
    ui->PacketView->setModel(sortingModel);
    ui->PacketView->setSortingEnabled(true);


    metaPanel = new MetaInfoPanel();
    QVBoxLayout * mainGrid = qobject_cast<QVBoxLayout*>(ui->MainGrid->layout());
    mainGrid->addWidget(metaPanel);
    frame_row_selected = ui->PacketView->selectionModel();
    connect(frame_row_selected, &QItemSelectionModel::currentRowChanged, this, &MainWindow::ShowDetailed);
    connect(ui->PacketView, SIGNAL(clicked(QModelIndex)), this, SLOT(ShowPacketDetailed(QModelIndex)));
    connect(ui->ProtoDetailWidget, SIGNAL(currentChanged(int)), this, SLOT(SetTabIndex(int)));
    connect(ui->filterExpr, &QLineEdit::returnPressed, this, &MainWindow::SetFilter);
    connect(this, &MainWindow::FilterTriggered, sortingModel, &SortingProxyModel::apply_filter);

    SetupInitialConnects();

}

void MainWindow::SetupInitialConnects()
{
    connect(ui->Settings, &QPushButton::clicked, this, &MainWindow::ShowInterfaceWindow);
    connect(ui->StopCapture, &QPushButton::clicked, captureManager, &SessionManager::StopCapture);
    connect(ui->PrevPacket, &QPushButton::clicked, this, [=] () {} );
    connect(ui->NextPacket, &QPushButton::clicked, this, &MainWindow::ToNext);

    connect(ui->PacketView->model(), &QAbstractItemModel::rowsInserted, this,   [=] () { SetEnabledIterButtons(true); } );
    connect(ui->PacketView->model(), &QAbstractItemModel::modelReset, this,     [=] () { SetEnabledIterButtons(false); } );

    PacketTableModel * currModel = qobject_cast<PacketTableModel*>(sortingModel->sourceModel());
    connect(currModel, &PacketTableModel::countChanged, this, &MainWindow::CheckCurrentModelDataValidity);
    connect(captureManager, &SessionManager::countUpdated, this,
            [this] ()
            {
                calculateMetrics();

            }
        );
    connect(sortingModel, &SortingProxyModel::filterCountChanged, this, [this] (float count, float chunk)
            {
        metaPanel->setChunkCount((const size_t)chunk);
        updatePercents(count, chunk);
    });


    connect(sortingModel, &SortingProxyModel::filteringBegan, this, &MainWindow::DetachModel);
    connect(sortingModel, &SortingProxyModel::filteringEnded, this, &MainWindow::AttachModel);


    connect(captureManager, &SessionManager::modelClearStarted, this, &MainWindow::ResetAll);
    connect(captureManager, &SessionManager::modelClearFinished, this, &MainWindow::SetupAll);

    connect(CaptureSettings->getTableView(), &InterfaceView::deviceSelected, this, &MainWindow::startup);
    connect(captureManager, &SessionManager::statusChanged, this, &MainWindow::setProgramInformation);

    connect(captureManager, &SessionManager::fileRemoved, this, &MainWindow::updateFileInfo);
    connect(captureManager, &SessionManager::fileSaved, this, &MainWindow::updateFileInfo);

    connect(ui->OpenPcap, &QPushButton::clicked, this, &MainWindow::openForReadDump);
    connect(captureManager, &SessionManager::modelPopulateStarted, this, &MainWindow::ResetAll);
    connect(captureManager, &SessionManager::modelPopulateFinished, this, &MainWindow::SetupAll);

    connect(captureManager, &SessionManager::got_filename, this, [=] (const QString & fname)
    {
        QFile __dumpInfo{fname};
        QFileInfo fi{fname};
        file_path = fname;
        setWindowTitle(fi.fileName());
        metaPanel->addFileName(fi.fileName());
    });
}


void MainWindow::PrepareSession()
{
    //captureManager->DevicePrepare();
}

Ui::MainWindow* MainWindow::GetUI() { return ui; }

void MainWindow::HandlePacketOutput(const FrameInfo & frame)
{
//    tmodel->append(frame);
}

void MainWindow::setOpenedState(bool flag)
{
    is_options_widget_opened = flag;
}


void MainWindow::ShowInterfaceWindow()
{
    if (is_options_widget_opened) return;
    CaptureSettings->show();
}

void MainWindow::SetEnabledStopCapture(bool flag)
{
    ui->StopCapture->setEnabled(flag);
}

void MainWindow::SetEnabledSaveCapture(bool flag)
{

}

void MainWindow::SetEnabledStartCapture(bool flag)
{
    ui->StartCapture->setEnabled(flag);
}

void MainWindow::SetEnabledCaptureOptions(bool flag)
{
    ui->Settings->setEnabled(flag);
}

void MainWindow::SetEnabledIterButtons(bool flag)
{
    ui->NextPacket->setEnabled(flag);
    ui->PrevPacket->setEnabled(flag);
}

void MainWindow::SetEnabledOpenPcapDump(bool flag)
{
    ui->OpenPcap->setEnabled(flag);
}

void MainWindow::ShowPacketDetailed(const QModelIndex & index)
{

    QModelIndex mappedIndex = sortingModel->mapToSource(index);

    if (!mappedIndex.isValid()) return;

    int row = mappedIndex.row();
    PacketTableModel * packets = qobject_cast<PacketTableModel*>(captureManager->getModel());


    if (is_locked())
    {
        if (tabsAllocated > 0)
        {
            FreeAllTabs();
        }
        hex_view->reset();
    }

    else
    {

        auto List = packets->get_list_ptr();

        auto begin = List->begin();
        auto end = List->end();

        if (begin == end) return;

        const FrameInfo & value = packets->get(row);

        delete currentFrame;
        currentFrame = new FrameInfo(value);

        if (tabsAllocated > 0)
        {
            FreeAllTabs();
        }


        tabs = new GenericTab*[TAB_MAX];

        tabs[GNINFO_INDEX] = new GenericTab(TabType::General, currentFrame, nullptr);
        tabs[ETH_INDEX] = new GenericTab(TabType::Ethernet, currentFrame, nullptr);

        tabs[GNINFO_INDEX]->getTab()->pinfo->commit();
        tabs[ETH_INDEX]->getTab()->eth->commit();


        ui->ProtoDetailWidget->addTab(tabs[GNINFO_INDEX]->getMainWidget(),  GENERAL_TAB_NAME_RU);
        ui->ProtoDetailWidget->addTab(tabs[ETH_INDEX]->getMainWidget(),     ETHERNET_TAB_RUS);

        tabsAllocated += 2;

        auto __getProtocolName = [](TabType type) -> QString
        {
            switch (type)
            {
            case TabType::V4: return  tr(IPv4_TAB_RU);
            case TabType::ARP: return tr("Протокол определения адреса (ARP)");
            case TabType::TCP: return tr("Протокол управления передачей (TCP)");
            case TabType::UDP: return tr("Протокол датаграмм клиента (UDP)");
            case TabType::ICMP: return tr("Протокол управления интернет сообщениями (ICMP)");
            case TabType::DNS: return tr("Система доменных имен (DNS)");
            }
            return tr("Unknown");
        };




        ProtocolHolder * proto_node = currentFrame->p_ref->First();

        int tab_index = 2;
        for (; proto_node; proto_node = proto_node->next)
        {
            bool is_valid = false;
            BaseTabWidget * basic_tab = nullptr;
            ParentArea * mwidget = nullptr;
            TabType type;
            switch (proto_node->type)
            {
            case CurrentIPv4:
            {
                tabs[tab_index] = new GenericTab(TabType::V4, &value, proto_node);
                basic_tab = tabs[tab_index]->getTab()->v4;
                mwidget = tabs[tab_index]->getMainWidget();
                is_valid = true;
                tabsAllocated++;
                type = TabType::V4;
                break;
            }
            case CurrentARP:
            {
                tabs[tab_index] = new GenericTab(TabType::ARP, &value, proto_node);
                basic_tab = tabs[tab_index]->getTab()->_arp;
                mwidget = tabs[tab_index]->getMainWidget();
                is_valid = true;
                tabsAllocated++;
                type = TabType::ARP;
                break;
            }
            case CurrentTCP:
            {
                tabs[tab_index] = new GenericTab(TabType::TCP, &value, proto_node);
                basic_tab = tabs[tab_index]->getTab()->_tcp;
                mwidget = tabs[tab_index]->getMainWidget();
                is_valid = true;
                tabsAllocated++;
                type = TabType::TCP;
                break;
            }
            case CurrentUDP:
            {
                tabs[tab_index] = new GenericTab(TabType::UDP, &value, proto_node);
                basic_tab = tabs[tab_index]->getTab()->_udp;
                mwidget = tabs[tab_index]->getMainWidget();
                is_valid = true;
                tabsAllocated++;
                type = TabType::UDP;
                break;
            }
            case CurrentICMP:
            {
                tabs[tab_index] = new GenericTab(TabType::ICMP, &value, proto_node);
                basic_tab = tabs[tab_index]->getTab()->_icmp;
                mwidget = tabs[tab_index]->getMainWidget();
                is_valid = true;
                tabsAllocated++;
                type = TabType::ICMP;
                break;
            }
            case CurrentDNS:
            {
                tabs[tab_index] = new GenericTab(TabType::DNS, &value, proto_node);
                basic_tab = tabs[tab_index]->getTab()->_dns;
                mwidget = tabs[tab_index]->getMainWidget();
                is_valid = true;
                tabsAllocated++;
                type = TabType::DNS;
                break;
            }

            default: is_valid = false;

            }

            if (is_valid)
            {
                basic_tab->commit();
                ui->ProtoDetailWidget->addTab(mwidget, __getProtocolName(type));
                tab_index++;
            }

        }

        hex_view->setData(currentFrame->copy, currentFrame->cap_len);
    }


    //qDebug() << tabsAllocated << '\n';

}

void MainWindow::ShowDetailed(const QModelIndex & current, const QModelIndex & previous)
{
    ShowPacketDetailed(current);
}

void MainWindow::SetTabIndex(int index)
{
    selectedTab = index;
}

void MainWindow::SetFilter()
{
    QString expr = ui->filterExpr->text();
    if (expr.isEmpty())
    {
        emit FilterTriggered(expr, false);
    }
    else
    {
        emit FilterTriggered(expr, true);

    }

    if (tabsAllocated)
    {
        FreeAllTabs();
    }
    hex_view->reset();
}

void MainWindow::ToNext()
{

    auto onViewModel = ui->PacketView->model();
    if (onViewModel)
    {
        QItemSelectionModel * selectionModel = ui->PacketView->selectionModel();
        QModelIndex current = selectionModel->currentIndex();
        QModelIndex next = onViewModel->index(current.row() + 1, current.column());

        selectionModel->setCurrentIndex(next, QItemSelectionModel::ToggleCurrent);
        ShowPacketDetailed(next);
    }
}

void MainWindow::ToPrevious()
{
    auto onViewModel = ui->PacketView->model();
    if (onViewModel)
    {
        QItemSelectionModel * selectionModel = ui->PacketView->selectionModel();
        QModelIndex current = selectionModel->currentIndex();
        QModelIndex prev = onViewModel->index(current.row() - 1, current.column());

        selectionModel->setCurrentIndex(prev, QItemSelectionModel::ToggleCurrent);
        ShowPacketDetailed(prev);
    }
}

void MainWindow::proxySetTotalCount()
{
    //metaPanel->setTotalCountInt(sortingModel->sourceModel()->rowCount());
}

void MainWindow::proxySetPercentCount(float ncount)
{
    //metaPanel->setPercentCountInt(ncount);
}

void MainWindow::proxyRefilter(const QString & pattern, bool enable_filter)
{
    //sortingModel->refilterAlreadyFiltered();
}

void MainWindow::resetHexPanel()
{
    getHexPanel()->reset();
}

void MainWindow::resetProtoViewPanel()
{
    if (tabsAllocated > 0)
    {
        FreeAllTabs();
    }
}

void MainWindow::reconnect_selection_signals()
{
    QItemSelectionModel * selectionModel = ui->PacketView->selectionModel();
    connect(selectionModel, &QItemSelectionModel::currentRowChanged, this, &MainWindow::ShowDetailed);
    connect(ui->PacketView, &QTableView::clicked, this, &MainWindow::ShowPacketDetailed);
}

void MainWindow::sort(int index, Qt::SortOrder order)
{

}

void MainWindow::updateCount()
{
    auto model = sortingModel->sourceModel();
    size_t count = 0;

    if (model)
    {
        count = model->rowCount();
    }

    metaPanel->setTotalCount(count);
}

void MainWindow::updateChunkCount()
{
    auto model = ui->PacketView->model();
    size_t count = 0;

    if (model)
    {
        count = model->rowCount();
    }

    metaPanel->setChunkCount(count);
}

void MainWindow::calculateMetrics()
{
    updateCount();
    updateChunkCount();
    auto counts_ = getCurrentCounts();
    updatePercents(static_cast<float>(counts_.first), static_cast<float>(counts_.second));

    QFile cpt_file{};
    cpt_file.setFileName(file_path);
    cpt_file.open(QIODevice::ReadOnly);
    metaPanel->updateFileInfo(cpt_file);
}

void MainWindow::updatePercents(float total, float chunk)
{
    const float percent = PacketTableModel::calculatePercent(total, chunk);
    metaPanel->setPercentCount(percent);
}

void MainWindow::CheckCurrentModelDataValidity(const size_t size, const size_t cap)
{
    if (size == cap)
    {
        locked_for_view = true;
    }
    else
    {
        locked_for_view = false;
    }
}

void MainWindow::DetachModel()
{
    ui->PacketView->setModel(nullptr);
    hex_view->reset();
    if (tabsAllocated) FreeAllTabs();
}

void MainWindow::AttachModel()
{
    ui->PacketView->setModel(sortingModel);
    reconnect_selection_signals();
    ui->PacketView->setSortingEnabled(true);
}

void MainWindow::ResetAll()
{
    DetachModel();
    metaPanel->setTotalCount(0);
    metaPanel->setChunkCount(0);
    metaPanel->setPercentCount(0.0f);

    metaPanel->addWarning("Resetting model ...");
}

void MainWindow::SetupAll()
{
    AttachModel();
    calculateMetrics();
    metaPanel->removeWarning();
}

SortingProxyModel *MainWindow::getSortingModel()
{
    return sortingModel;
}

MyHexView *MainWindow::getHexPanel()
{
    return hex_view;
}

void MainWindow::SetFont(const QFont &_font)
{
    auto header_font = QFont("Sans Serif", 8);
    header_font.setStyleHint(QFont::SansSerif);
    ui->PacketView->setFont(_font);
    ui->PacketView->horizontalHeader()->setFont(header_font);
}

void MainWindow::FreeAllTabs() noexcept
{
    for (unsigned i = 0; i < tabsAllocated; i++) delete tabs[i];
    tabsAllocated = 0;
    ui->ProtoDetailWidget->clear();
}

bool MainWindow::is_locked() const
{
    return locked_for_view;
}

QPair<size_t, size_t> MainWindow::getCurrentCounts()
{
    auto srcModel = sortingModel->sourceModel();
    auto inViewModel = ui->PacketView->model();

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
    delete ui;
}

void MainWindow::openForReadDump()
{
    captureManager->LoadCaptureFile();
}

void MainWindow::updateFileInfo()
{
    CaptureSettings->prepareFile();
    file_name = CaptureSettings->getFilename();
    file_path = CaptureSettings->getFullPath();

    QFile cpt_file{};
    cpt_file.setFileName(file_path);
    cpt_file.open(QIODevice::ReadOnly);
    metaPanel->updateFileInfo(cpt_file);
}

void MainWindow::CreateMessageBox(const QString &title, const QString &description, const QIcon &ico)
{
    QMessageBox alert;
    alert.setText(description);
    alert.setWindowTitle(title);
    alert.setWindowIcon(ico);
    alert.exec();
}

void MainWindow::startup()
{
    const InterfaceItem * item = CaptureSettings->getTableView()->getSelectedItem();
    setInterface(item);
    CaptureSettings->hide();
    captureManager->setInterface(&currentInterface);
    CaptureSettings->prepareFile();

    file_name = CaptureSettings->getFilename();
    file_path = CaptureSettings->getFullPath();

    captureManager->setFileWritePath(file_path);
    metaPanel->addFileName(file_name);
    captureManager->StartCapture();
}

void MainWindow::setInterface(const InterfaceItem *_interface)
{
    currentInterface = _interface;
}

void MainWindow::setProgramInformation(SessionManager::CaptureStatus status)
{
    QString statusTitle;
    if (status == SessionManager::CaptureStatus::Started)
    {
        auto link_type = pcap_datalink(captureManager->getOpenHandle());
        statusTitle = "Проводится захват";

        if (currentInterface)
        {
            statusTitle += tr(" Тип устройства: [ ");
            DeviceType type = currentInterface->getType();
            switch (type)
            {
            case DeviceType::Unknown: statusTitle += tr("Неизвестное устройство"); break;
            case DeviceType::Ethernet: statusTitle += tr("Ethernet"); break;
            case DeviceType::Wireless: statusTitle += tr("Беспроводное"); break;
            case DeviceType::Loopback: statusTitle += tr("Loopback"); break;
            case DeviceType::Other: statusTitle+= tr("Другое"); break;
            }

            statusTitle += QString(" ] имя: %1").arg(currentInterface->getFriendlyName());
            metaPanel->setDeviceName(currentInterface->getFriendlyName());
        }
        SetEnabledCaptureOptions(false);
        SetEnabledStopCapture(true);
        SetEnabledOpenPcapDump(false);
    }
    else
    {
        locked_for_view = false;
        sortingModel->setLock(false);
        statusTitle = tr("Захват остановлен");
        SetEnabledCaptureOptions(true);
        SetEnabledStopCapture(false);
        SetEnabledOpenPcapDump(true);
    }



    setWindowTitle(statusTitle);
}

