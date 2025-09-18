#include <QObject>
#include <pcap/pcap.h>
#include "if_choose.h"

int InitPcapLib(uint32_t, char*);
void LoadInterfaces(if_choose*, char*, void*, pcap_if_t**);
