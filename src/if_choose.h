#ifndef IF_CHOOSE_H
#define IF_CHOOSE_H

#include <QWidget>
#include "mainwindow.h"
#include "interface_widget.h"
#include "ui_if_choose.h"


typedef void(MainWindow::*state_handler)(bool);

namespace Ui {
class if_choose;
}

class if_choose : public QWidget, public std::vector<pcap_if_t*>
{
    Q_OBJECT

public:
    explicit if_choose(MainWindow*, QWidget *parent = nullptr);
    auto GetUI() {return ui;}
    void SetHandler(state_handler);

    ~if_choose();
    void BeginLoading();
private:
    Ui::if_choose *ui;
    state_handler callback;
    MainWindow * mWindowRef;
    pcap_if_t * devices_;
    int CurrentRow, LastRow, SelectionCount;
    bool DeviceStarted;
    bool CaptureStarted;
    char errbuf[PCAP_ERRBUF_SIZE];

    void RegisterSignals();

protected:
    void showEvent(QShowEvent *) override;
    void closeEvent(QCloseEvent * p) override;

private slots:


    void StartCaptureSlot();
    void CloseSlot();
    void SetCurrentRow(int, int);
    void SetButtonStartEnabled(bool);
signals:
    void DeviceSelected(bool);
    void DisableOptsButton(bool);
};

#endif // IF_CHOOSE_H
