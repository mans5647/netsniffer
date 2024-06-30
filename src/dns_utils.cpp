#include "dns_utils.h"
#include "helpers.h"
#include <string>

size_t ParseAnswer(const uint8_t* a_data, const uint8_t * dns_begin, DnsAnswer* answer)
{
    auto off = (uint16_t*)a_data; // 2
    auto type = (uint16_t*)(a_data + 2); // 2
    auto cl = (uint16_t*)(a_data + 4); // 2
    auto ttl = (uint32_t*)(a_data + 6); // 4
    auto len = (uint16_t*)(a_data + 10); // 2
    in_addr* hostaddr = nullptr;
    const uint8_t* hostname;
    const uint8_t* cname_ = nullptr;

    answer->offset = ntohs(*off);
    answer->type = ntohs(*type);
    answer->cl_name = ntohs(*cl);
    answer->ttl = ntohl(*ttl);
    answer->length = ntohs(*len);

    auto nlen = ntohs(*len);

    auto data = a_data + DNS_ANSWER_MEMBER_CONST_SIZE;

    auto name_data = (dns_begin + (DNS_NAME_OFFCALC(answer->offset))); // skip leading dot .

    int it_name = 0;
    for (; *name_data++ != '\0';)
    {
        if (IsPrintable(name_data)) answer->name[it_name] = *name_data;
        else answer->name[it_name] = '.';
        it_name++;
    }

    answer->name[it_name - 1] = '\0';

    if (answer->length <= 4)
    {
        if (answer->length == 2)
        {
            auto offsz = (uint16_t*)data;
            auto lendian_value = ntohs(*offsz);
            auto value = (lendian_value & 255);

            cname_ = dns_begin + value;


        }
        else if (answer->length == 4)
        {
            hostaddr = (in_addr*)(data);
        }
    }
    else
    {
        hostname = data;
    }


    if (answer->type == DNS_TYPE_A && answer->length == 4)
    {
        memcpy(&answer->adata.host_addr.address, hostaddr, sizeof(in_addr));
    }
    else if (answer->type == DNS_TYPE_CNAME && answer->length == 2)
    {
        int j = 0;
        for (; *cname_ != '\0'; cname_++)
        {
            if (IsPrintable(cname_))
                answer->adata.cname.data[j] = *cname_;
            else answer->adata.cname.data[j] = '.';
            j++;
        }
        answer->adata.cname.data[j - 1] = '\0';
    }
    else if (answer->type == DNS_TYPE_CNAME && answer->length > 4)
    {
        int i;
        for (i = 0; i < answer->length; i++)
        {
            if (IsPrintable(data))
                answer->adata.cname.data[i] = *data;
            else answer->adata.cname.data[i] = '.';
            data++;
        }
        answer->adata.cname.data[i - 1] = '\0';
    }

    return nlen + DNS_ANSWER_MEMBER_CONST_SIZE;

}

size_t ParseQuestion(const uint16_t q_count, const uint8_t* n_data_dns, DnsQuestion * question)
{

    const uint8_t* qaddr = (n_data_dns + DNS_HEADER_SIZE);
    int name_offset = 0;
    const uint8_t* q_addr_begin = qaddr;
    QByteArray dirty_name;
    while (true)
    {
        if (*qaddr == '\0') break;
        if (IsPrintable(qaddr)) dirty_name.push_back(*qaddr);
        else dirty_name += '.';
        name_offset++;
        qaddr++;
    }

    const uint8_t* field_type = q_addr_begin + name_offset + 1;
    const uint8_t* field_class = q_addr_begin + name_offset + 3;
    auto t_value = (uint16_t*)(field_type);
    auto c_value = (uint16_t*)(field_class);

    question->type = ntohs(*t_value);
    question->cl_name = ntohs(*c_value);
    question->name = dirty_name.isEmpty() ? QByteArray() : dirty_name.sliced(1, dirty_name.size() - 1);
    //question->name[i] = '\0';
    //question->name++; // skip leading dot;

    return name_offset + 5;
}
