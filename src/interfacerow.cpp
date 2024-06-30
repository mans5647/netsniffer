#include "interfacerow.h"


InterfaceRow::InterfaceRow(pcap_if_t ** dev)
{
    device = (*dev);


    for (auto i = 0; i < MAX_IFCOL; i++)
    {
        m_elements[i] = new QTableWidgetItem{};
    }

}

pcap_if_t **InterfaceRow::GetDevice()
{
    return &device;
}

void InterfaceRow::setAttribue_NO(int no)
{
    m_elements[IFCOL_NO]->setText(QString::number(no));
}

void InterfaceRow::setAttribute_DESC(const char * desc)
{
    m_elements[IFCOL_DESC]->setText(desc);
}

void InterfaceRow::setAttribute_TYPE(int flags)
{
    m_elements[IFCOL_TYPE]->setText(GetTypeFromFlags(flags));
}

void InterfaceRow::setAttribute_STAT(int flags)
{
    m_elements[IFCOL_STAT]->setText(GetStatusFromFlags(flags));
}

void InterfaceRow::setAttribue_LB(int flags)
{
    m_elements[IFCOL_LB]->setText(GetLoopbackSource(flags));
}

QTableWidgetItem *InterfaceRow::GetAt(size_t index)
{
    return m_elements[index];
}

const char *InterfaceRow::GetTypeFromFlags(int flags)
{
    static const char * __str;
    if (flags & PCAP_IF_WIRELESS)
    {
        __str = "Wireless device";
    }
    else
    {
        __str = "Other";
    }
    return __str;
}

const char *InterfaceRow::GetStatusFromFlags(int flags)
{
    static const char * __str;
    if (flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
    {
        __str = "Connected";
    }
    else if (flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
    {
        __str = "Disconnected";
    }
    else if (flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)
    {
        __str = "Not applicable";
    }
    else
    {
        __str = "Unknown";
    }
    return __str;
}

const char *InterfaceRow::GetLoopbackSource(int flags)
{
    static const char * __str;
    if (flags & PCAP_IF_LOOPBACK)
    {
        __str = "Loopback device";
    }
    else
    {
        __str = "Other";
    }
    return __str;
}
