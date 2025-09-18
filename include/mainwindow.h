#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <pcap/pcap.h>
#include <QPair>
#include "packet_row.h"
#include "packettablemodel.h"
#include "protocoldetailtab.h"
#include "sessionmanager.h"
#include "qhexview.h"

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
    using MainWindowPtrImpl = Ui::MainWindow*;
    static const char * ProgramName;

    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void SetOpenedState(bool);
    MainWindowPtrImpl GetUI();
    void SetupInitialConnects();
    QHexView * GetHexPanel();
    SortingProxyModel * GetSortingModel();
public slots:
    void OpenForReadDump();
    void UpdateFileInfo();
    void CreateMessageBox(const QString & title, const QString & description, const QIcon & ico);
    void Startup();
    void SetInterface(const InterfaceItem * _interface);
    void SetCaptureStatus(SessionManager::CaptureStatus status);
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
    void SetFilterAuto();
    void ToNext();
    void ToPrevious();
    void ResetHexPanel();
    void ResetProtoViewPanel();
    void ReconnectSelectionSignals();
    void SortPackets(int, Qt::SortOrder);
    void UpdatePacketCountAuto();
    void UpdateChunkCountAuto();
    void CalculateMetricsAuto();
    void UpdatePercent(float, float);

    void CheckCurrentModelDataValidity(const size_t size, const size_t cap);
    void DetachModel();
    void AttachModel();
    void ResetAll();
    void SetupAll();
private:

    SessionManager * capture_manager_;
    MainWindowPtrImpl ui_;
    SortingProxyModel * sorting_model_;
    QItemSelectionModel * frame_row_selected_;
    // GeneralInfoTab * info;
    // EthernetDetailTab * etab;
    // GenericTab ** tabs;
    QSplitter * delim;
    QHexView * hex_view;
    QLayout * tab_hex_layout;
    MetaInfoPanel * meta_panel_;
    CaptureSettingsDialog * cap_settings;

    bool        is_options_open_;
    bool        locked_for_view_;
    int         selected_tab_;
    unsigned    tabs_alloc_total = 0u;
    size_t selectedPacket;
    bool has_packets_;
    bool IsLocked() const;

    const InterfaceItem * current_interface_;
    const FrameInfo * current_viewing_frame_;
    FrameInfo * current_frame_;
    QByteArray current_hex_data_;
    QString file_path_;
    QString file_name_;

    void _SetFont(const QFont & _font);
    void _FreeAllTabs() noexcept;
    QPair<size_t, size_t> _GetCurrentCounts();


signals:
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
