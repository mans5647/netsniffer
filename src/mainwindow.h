#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <pcap/pcap.h>
#include <QPair>
#include "packet_row.h"
#include "packettablemodel.h"
#include "protocoldetailtab.h"
#include "sessionmanager.h"
#include "hexview.h"

#define COL_NO_WIDTH 10
#define COL_TIME_WIDTH 30
#define COL_SRC_WIDTH 40
#define COL_DST_WIDTH 40
#define COL_PROTO_WIDTH 30
#define COL_LEN_WIDTH 20
#define COL_INFO_WIDTH 60


#define TAB_MAX MAX_SUPPORT_PROTOS + 2
#define GNINFO_INDEX 0
#define ETH_INDEX 1

class QSplitter;
class MyHexView;
class SortingProxyModel;
struct Packet;
struct FrameInfo;
class MetaInfoPanel;
class CaptureSettingsDialog;
class InterfaceItem;
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE


class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    SessionManager * captureManager;
    static const char * program_name;

    MainWindow(QWidget *parent = nullptr);
    void setOpenedState(bool);
    void PrepareSession();
    Ui::MainWindow* GetUI();
    void SetupInitialConnects();
    MyHexView * getHexPanel();
    SortingProxyModel * getSortingModel();
    ~MainWindow();
public slots:
    void openForReadDump();
    void updateFileInfo();
    void CreateMessageBox(const QString & title, const QString & description, const QIcon & ico);
    void startup();
    void setInterface(const InterfaceItem * _interface);
    void setProgramInformation(SessionManager::CaptureStatus status);
    void HandlePacketOutput(const FrameInfo &);
    void ShowInterfaceWindow();
    void SetEnabledStopCapture(bool);
    void SetEnabledSaveCapture(bool);
    void SetEnabledStartCapture(bool);
    void SetEnabledCaptureOptions(bool);
    void SetEnabledIterButtons(bool);
    void SetEnabledOpenPcapDump(bool);

    void ShowPacketDetailed(const QModelIndex &);
    void ShowDetailed(const QModelIndex&, const QModelIndex &);
    void SetTabIndex(int);
    void SetFilter();
    void ToNext();
    void ToPrevious();
    void proxySetTotalCount();
    void proxySetPercentCount(float);
    void proxyRefilter(const QString &, bool);
    void resetHexPanel();
    void resetProtoViewPanel();
    void reconnect_selection_signals();
    void sort(int, Qt::SortOrder);
    void updateCount();
    void updateChunkCount();
    void calculateMetrics();
    void updatePercents(float total, float chunk);

    void CheckCurrentModelDataValidity(const size_t size, const size_t cap);
    void DetachModel();
    void AttachModel();
    void ResetAll();
    void SetupAll();
private:
    bool is_options_widget_opened;
    bool locked_for_view;
    Ui::MainWindow *ui;
    SortingProxyModel * sortingModel;
    QItemSelectionModel * frame_row_selected;


    GeneralInfoTab * info;
    EthernetDetailTab * etab;

    GenericTab ** tabs;
    int selectedTab;

    const InterfaceItem * currentInterface;
    QSplitter * delim;
    MyHexView * hex_view;
    QHBoxLayout * tab_hex_layout;
    MetaInfoPanel * metaPanel;
    CaptureSettingsDialog * CaptureSettings;
    const FrameInfo * currentViewingFrame;
    FrameInfo * currentFrame;
    unsigned tabsAllocated = 0u;
    size_t selectedPacket;
    bool has_packets;
    QString file_path;
    QString file_name;
    void SetFont(const QFont & _font);
    void FreeAllTabs() noexcept;
    bool is_locked() const;
    QPair<size_t, size_t> getCurrentCounts();


signals:
    void StopCapturing(void*);
    void RowAppended(const QTableWidgetItem*,QAbstractItemView::ScrollHint);
    void SetProgramTitle(const QString &);
    void AtLeastOneRowAppended(bool);
    void FilterTriggered(const QString &, bool);
protected:
    void closeEvent(QCloseEvent *event) override;
    void focusOutEvent(QFocusEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void leaveEvent(QEvent *event) override;
    void changeEvent(QEvent * event) override;

};


typedef void (MainWindow::*HandlePacket)(const FrameInfo &);


#endif // MAINWINDOW_H
