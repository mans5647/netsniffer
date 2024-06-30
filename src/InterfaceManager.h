#ifndef IF_M
#define IF_M
#endif

#include <pcap/pcap.h>
#include <string>
#include <vector>
#include <QObject>

using Interface = pcap_if_t*;


typedef void(*failure_callback)(const char *, int);

class InterfaceManager : public QObject
{
    Q_OBJECT
public slots:
    void load();
    void FreeInterfaces();
public:

    Interface get_at(int);
    Interface get_head() { return head; }

    auto GetDeviceCount() {
        int count = 0;
        while (head)
        {
            count++;
            head = head->next;
        }
        return count;
    }

signals:
    void finished();
private:
    Interface head = nullptr;
};


