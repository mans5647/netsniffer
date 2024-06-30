#include <QThread>
#include "if_loader.h"
#include "ui_if_choose.h"
#include "InterfaceManager.h"
#include "interface_widget.h"
#include "interfacerow.h"
#include <QTableWidgetItem>


int InitPcapLib(uint32_t opts, char *errbuf)
{
    if (!errbuf) throw;
    return pcap_init(opts, errbuf);
}


void LoadInterfaces(if_choose * context, char * errbuf, void * __unused, pcap_if_t** global_devsource)
{
    static bool is_loaded = false;
    if (!context)
        throw;
    if (!is_loaded)
    {
        InitPcapLib(0, errbuf);
        is_loaded = true;
    }

    auto status = pcap_findalldevs(global_devsource,errbuf);
    if (status == PCAP_ERROR)
    {

    }
    else
    {
        auto device = (*global_devsource);
        int d_count{};

        auto dev_alt = (*global_devsource);
        while (dev_alt)
        {
            d_count++;
            dev_alt = dev_alt->next;
        }


        QTableWidget * IF_Table = context->GetUI()->interface_list;
        IF_Table->setRowCount(d_count);
        int row = 0;
        while (device)
        {

            InterfaceRow * __iface = new InterfaceRow(&device);


            __iface->setAttribue_NO(row + 1);
            __iface->setAttribute_DESC(device->description);
            __iface->setAttribute_STAT(device->flags);
            __iface->setAttribute_TYPE(device->flags);
            __iface->setAttribue_LB(device->flags);

            IF_Table->setItem(row, IFCOL_NO,    __iface->GetAt(IFCOL_NO));
            IF_Table->setItem(row, IFCOL_DESC,  __iface->GetAt(IFCOL_DESC));
            IF_Table->setItem(row, IFCOL_TYPE,  __iface->GetAt(IFCOL_TYPE));
            IF_Table->setItem(row, IFCOL_STAT,  __iface->GetAt(IFCOL_STAT));
            IF_Table->setItem(row, IFCOL_LB,    __iface->GetAt(IFCOL_LB));
            context->push_back(device);
            row++;
            device = device->next;
        }
    }
}
