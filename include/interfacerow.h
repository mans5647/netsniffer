#ifndef INTERFACEROW_H
#define INTERFACEROW_H

#include <QObject>
#include <QTableWidgetItem>
#include <pcap/pcap.h>


#define MAX_IFCOL       5

#define IFCOL_NO        0
#define IFCOL_DESC      1
#define IFCOL_TYPE      2
#define IFCOL_STAT      3
#define IFCOL_LB        4

class InterfaceRow : public QObject
{
    Q_OBJECT
public:
    InterfaceRow(pcap_if_t**);
    pcap_if_t **GetDevice(void);
    void setAttribue_NO(int);
    void setAttribute_DESC(const char*);
    void setAttribute_TYPE(int);
    void setAttribute_STAT(int);
    void setAttribue_LB(int);

    QTableWidgetItem * GetAt(size_t);

private:

    QTableWidgetItem * m_elements[MAX_IFCOL];   // interface elements to show on
    pcap_if_t * device;                         // device itself, row holds it


    const char* GetTypeFromFlags(int);
    const char* GetStatusFromFlags(int);
    const char* GetLoopbackSource(int);
};

#endif // INTERFACEROW_H
