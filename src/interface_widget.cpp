#include "interface_widget.h"

pcap_if_t * interface_widget::GetDeviceHandle()
{
    return device_handle;
}

void interface_widget::setDeviceHandle(pcap_if_t * handle)
{
    device_handle = handle;
}
