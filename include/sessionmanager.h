#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include <QString>
#include <QThread>
#include <QTableWidget>
#include <QMessageBox>
#include <QMutex>
#include <pcap/pcap.h>
#include "helpers.h"
#include "proto_list.h"
#include "interfaceitem.h"

class PacketTableModel;


class QFileDialog;

class SessionManager : public QObject
{
    Q_OBJECT
public:

    enum class CaptureStatus
    {
        Started,
        Stopped
    };

    SessionManager();
    ~SessionManager();

    static SessionManager * getInstance();

    QAbstractItemModel * GetPackets(); // getModel
    void StartCapture();
    bool IsOpened();

signals:
    void FileSaved();
    void FileRemoved();
    void ModelPopulateStarted();
    void ModelPopulateFinished();
    void FileNameFetched(const QString & fname);
    void StatusChanged(CaptureStatus);
    void CountUpdated();
    void ModelClearStarted();
    void ModelClearFinished();

public slots:
    void LoadCaptureFile();
    bool RemoveTempFile();
    void SaveCaptureFile();
    void FreeResources();
    void SetDumpWritePath(const QString & absolute_path);
    void StopCapture();
    void OpenNewSession();
    pcap_t * GetRawCaptureHandle();
    void SetInterface(const InterfaceItem * item);
private:

    static SessionManager   *   instance;
    pcap_t                  *   capture_handle;
    QThread                 *   capture_thread;
    QThread                 *   read_thread;
    QMessageBox             *   save_changes_msgbox;
    const InterfaceItem     *   current_interface;
    pcap_dumper_t           *   file_dumper;
    QFileDialog             *   file_dialog;
    PacketTableModel        *   packets;
    bool                        save_to_file;
    char                        pcap_error_buf[PCAP_ERRBUF_SIZE];
    QString                     absolute_path;
    QString                     old_path;

    void doCaptureLoop();
    void setupModel();
    void liveCapture();
    void openForRead(const char * filename);
    void readAllPacketsToModel();
    ether_header parseEthernetHeader(const uint8_t*);
    // void parseNetworkLayer(FrameInfo*, const uint8_t*);
    // void parseTransportLayer(FrameInfo *, const uint8_t*);
    // void parseApplicationLayerProto(FrameInfo*, const uint8_t*, uint32_t);
};



#endif // SESSIONMANAGER_H
