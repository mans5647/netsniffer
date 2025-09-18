#ifndef INTERFACE_WIDGET_H
#define INTERFACE_WIDGET_H
#include <QTableWidgetItem>
#include <QString>
#include <pcap/pcap.h>

class interface_widget : public QTableWidgetItem
{
public:
    interface_widget(const QString & txt_displayed) : QTableWidgetItem(txt_displayed) {}
    pcap_if_t * GetDeviceHandle();
    pcap_if_t * GetDeviceSource() { return device_source; }
    void setDeviceHandle(pcap_if_t*);
    void setDeviceSource(pcap_if_t* src) { device_source = src; }
private:
    pcap_if_t * device_handle;
    pcap_if_t * device_source;

};

#endif // INTERFACE_WIDGET_H
