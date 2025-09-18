#include "dns_utils.h"
#include "helpers.h"
#include <string>

std::ptrdiff_t ParseAnswer(const uint8_t* aAddr, DnsAnswer* answer)
{
    auto off = (uint16_t*)aAddr; // 2
    auto type = (uint16_t*)(aAddr+ 2); // 2
    auto cl = (uint16_t*)(aAddr + 4); // 2
    auto ttl = (uint32_t*)(aAddr + 6); // 4
    auto len = (uint16_t*)(aAddr + 10); // 2
    in_addr* hostaddr = nullptr;
    const uint8_t* hostname;
    const uint8_t* cname_ = nullptr;

    answer->offset = ntohs(*off);
    answer->type = ntohs(*type);
    answer->cl_name = ntohs(*cl);
    answer->ttl = ntohl(*ttl);
    answer->length = ntohs(*len);

    auto nlen = ntohs(*len);

    auto data = aAddr + DNS_ANSWER_MEMBER_CONST_SIZE;

    auto name_data = (aAddr + (DNS_NAME_OFFCALC(answer->offset))); // skip leading dot .

    int it_name = 0;
    for (; *name_data++ != '\0';)
    {
        if (isPrintable(*name_data)) answer->name[it_name] = *name_data;
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

            cname_ = aAddr + value;
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
            if (isPrintable(*cname_))
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
            if (isPrintable(*data))
                answer->adata.cname.data[i] = *data;
            else answer->adata.cname.data[i] = '.';
            data++;
        }
        answer->adata.cname.data[i - 1] = '\0';
    }

    return nlen + DNS_ANSWER_MEMBER_CONST_SIZE;

}

std::ptrdiff_t ParseQuestion(const uint8_t* qaddr, DnsQuestion * question)
{
    while (*qaddr)
    {
        if (isPrintable(*qaddr))
            question->name += *qaddr;
        else question->name += '.';
        qaddr++;
    }

    const uint8_t* field_type = qaddr + question->name.size() + 1;
    const uint8_t* field_class = qaddr + question->name.size() + 3;

    question->type = ntohs(*(uint16_t*)(field_type));
    question->cl_name = ntohs(*(uint16_t*)(field_class));
    return question->name.size() + 5;
}
