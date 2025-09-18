#ifndef DNSRECORDSSECTION_H
#define DNSRECORDSSECTION_H

#include <vector>
#include <QVBoxLayout>
#include <QWidget>
class DnsQuestionEntry;
class DnsAnswerEntry;

enum class RecordType
{
    Question,
    Answer,
};

class DnsRecordsSection : public QWidget
{
public:
    DnsRecordsSection(RecordType type, const void * questions, size_t n);
    ~DnsRecordsSection() noexcept;
    size_t count() const;
    size_t single_record_height() const;
private:
    using QListType = std::vector<DnsQuestionEntry*>;
    using AListType = std::vector<DnsAnswerEntry*>;
    QListType q_entries;
    AListType a_enteries;
    QVBoxLayout * m_layout;
    QSpacerItem * spacer;
    RecordType current;

};

#endif // DNSRECORDSSECTION_H
