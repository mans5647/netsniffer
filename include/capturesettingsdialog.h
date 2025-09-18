#ifndef CAPTURESETTINGSDIALOG_H
#define CAPTURESETTINGSDIALOG_H

#include <QWidget>
#include <QScrollArea>
#include <QSpacerItem>
#include <QGroupBox>
#include <QLineEdit>
#include <pcap/pcap.h>

class QTabWidget;
class QLabel;
class QVBoxLayout;
class QHBoxLayout;
class QTableView;
class QPushButton;
class InterfaceView;

class FileSettingsView;

class CaptureSettingsDialog : public QWidget
{
public:
    CaptureSettingsDialog();
    ~CaptureSettingsDialog();

    InterfaceView * getTableView();
    FileSettingsView * getFileSettings();
    QString getFullPath() const;
    QString getLocation() const;
    QString getFilename() const;
public slots:
    void prepareFile();

private:

    class BaseArea : public QScrollArea
    {
    public:
        BaseArea(QWidget * parent = nullptr);
        void addWidgetToLayout(QWidget * widget);
    private:
        QVBoxLayout * areaLayout;
    };

    class InterfaceArea : public BaseArea
    {
    public:
        InterfaceArea(QWidget * parent = nullptr);
    };

    class FileArea : public BaseArea
    {
    public:
        FileArea(QWidget * parent = nullptr);
    };

    InterfaceArea   * if_area;
    FileArea        * file_area;

    QPixmap             ic_reload;
    QGroupBox           * action_box;
    QTabWidget          * tabs;
    QPushButton         * reload_ifaces_btn;
    QPushButton         * apply;
    QPushButton         * cancel;
    QSpacerItem         * delimeter;
    QVBoxLayout         * mLayout;
    QHBoxLayout         * action_box_layout;
    InterfaceView       * device_table;
    FileSettingsView    * file_settings;



    const QString widgetName = QString(tr("Настройки захвата"));
    const QString tab_if_name = QString(tr("Интерфейсы"));
    const QString tab_file_settings_name = QString(tr("Настройки записи файла"));

};

#endif // CAPTURESETTINGSDIALOG_H
