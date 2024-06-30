#include "InterfaceManager.h"
#include <QWidget>


void InterfaceManager::load()
{
    char local_errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&head, local_errbuf) == PCAP_ERROR)
        return;
}


void InterfaceManager::FreeInterfaces()
{
    pcap_freealldevs(head);
}
