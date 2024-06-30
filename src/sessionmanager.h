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
private:

    static SessionManager * instance;
    SessionManager();

    QMutex * mtx;
    pcap_if_t   *   device_source;
    pcap_if_t   *   device_handle;
    pcap_t      *   capturing_handle;
    QThread     *   cpt_thread;
    QThread     *   readThread;
    QMessageBox * saveChanges;
    const InterfaceItem * m_interface;
    bool saveFile;
    char            local_error_buf[PCAP_ERRBUF_SIZE];
    PacketTableModel * framesModel;
    QString absolute_path;
    QString old_path;
    QFileDialog * mf_dialog;
    pcap_dumper_t * fileDumper;
    char errorbuf[PCAP_ERRBUF_SIZE];
    void capture_thread(pcap_t**);
    void setModel();

public:

    enum class CaptureStatus
    {
        Started,
        Stopped
    };

    static SessionManager * getInstance()
    {
        if (!instance)
        {
            instance = new SessionManager();
        }
        return instance;
    }





    void StartCapture();
    QAbstractItemModel * getModel();

    bool IsOpened();


    void ParseFrame(FrameInfo*, const uint8_t *);
    ether_header ParseEthernetHeader(const uint8_t*);
    void ParseNetworkLayer(FrameInfo*, const uint8_t*);
    void ParseTransportLayer(FrameInfo *, const uint8_t*);
    void ParseApplicationLayerProto(FrameInfo*, const uint8_t*, uint32_t);

    ~SessionManager();

signals:
    void fileSaved();
    void fileRemoved();
    void modelPopulateStarted();
    void modelPopulateFinished();
    void got_filename(const QString & fname);
    void statusChanged(CaptureStatus);
    void titleChanged(const QString & text);
    void FrameReceived(const FrameInfo*);
    void CaptureStopped_setButtonOPTS(bool);
    void CaptureStopped_setButtonFILE(bool);
    void CaptureStopped_setButtonSTART(bool);
    void CaptureStopped_setButtonSTOP(bool);
    void countUpdated();
    void requestToFilterTriggered(const QString &, bool);
    void modelIsAbouToResize();
    void modelResizeFinished();
    void modelClearStarted();
    void modelClearFinished();

public slots:
    void LoadCaptureFile();
    void mock();
    bool RemoveTempFile();
    void SaveCaptureFile();
    void FreeResources();
    void setFileWritePath(const QString & absolute_path);
    void StopCapture(bool);
    void opendevice();
    void open_new_session();
    pcap_t * getOpenHandle();
    void setInterface(const InterfaceItem ** item);
private:
    void LiveCapture();
    void open_file_for_read(const char * filename);
    void ReadAllPacketsToModel();
};



#endif // SESSIONMANAGER_H
