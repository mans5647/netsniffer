#ifndef DNSANSWERENTRY_H
#define DNSANSWERENTRY_H


#include "keyvaluepairwidget.h"
#include "dns.h"
#include <QWidget>
#include <QVBoxLayout>

class DnsAnswerEntry : public QWidget
{
public:
    DnsAnswerEntry(const DnsAnswer & answer);
    ~DnsAnswerEntry() noexcept;

private:

    KeyValuePairWidget * nameField;
    KeyValuePairWidget * typeField;
    KeyValuePairWidget * classField;
    KeyValuePairWidget * ttlField;
    KeyValuePairWidget * lenField;
    KeyValuePairWidget * dataField;


    QLabel * name, * type, * cl, * ttl, * len, * data;
    QVBoxLayout * mLayout;
};

#endif // DNSANSWERENTRY_H
