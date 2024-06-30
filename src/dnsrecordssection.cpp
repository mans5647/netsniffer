#include "dnsrecordssection.h"
#include "dnsquestionentry.h"
#include "dnsanswerentry.h"

DnsRecordsSection::DnsRecordsSection(RecordType type, const void *src, size_t n)
{
    m_layout = new QVBoxLayout{};
    spacer = new QSpacerItem(20, 50, QSizePolicy::Expanding, QSizePolicy::Minimum);
    current = type;


    if (type == RecordType::Question)
    {
        DnsQuestion * source = (DnsQuestion*)src;
        q_entries.reserve(n);
        for (auto i = 0; i < n; i++)
        {
            q_entries.push_back(new DnsQuestionEntry(source[i]));
            m_layout->addWidget(q_entries.at(i));
            //m_layout->addSpacerItem(spacer);
        }

    }

    else
    {
        DnsAnswer * source = (DnsAnswer*)src;
        a_enteries.reserve(n);

        for (auto i = 0; i < n; i++)
        {
            a_enteries.push_back(new DnsAnswerEntry(source[i]));
            m_layout->addWidget(a_enteries.at(i));
            //m_layout->addSpacerItem(spacer);
        }

    }

    setLayout(m_layout);
}

DnsRecordsSection::~DnsRecordsSection() noexcept
{
    switch (current)
    {
    case RecordType::Answer:
    {
        for (auto i : a_enteries)
            delete i;

        a_enteries.clear();
        break;
    }
    case RecordType::Question:
    {
        for (auto i : q_entries)
            delete i;

        q_entries.clear();

        break;
    }
    }

    delete m_layout;
}

size_t DnsRecordsSection::count() const
{
    return (current == RecordType::Question) ? q_entries.size() : a_enteries.size();
}

size_t DnsRecordsSection::single_record_height() const
{
    switch (current)
    {
    case RecordType::Question:
    {
        if (count() > 0)
        {
            auto itr = q_entries.front();
            return itr->height();
        }
        return 0;
    }
    case RecordType::Answer:
    {
        if (count() > 0)
        {
            auto itr = a_enteries.front();
            return itr->height();
        }
        return 0;
    }
    }
}
