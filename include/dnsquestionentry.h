#ifndef DNSQUESTIONENTRY_H
#define DNSQUESTIONENTRY_H


#include "keyvaluepairwidget.h"
#include "dns.h"
#include <QWidget>

class DnsQuestionEntry : public QWidget
{
public:

    DnsQuestionEntry(const DnsQuestion & question);
    ~DnsQuestionEntry() noexcept;
private:

    KeyValuePairWidget  * nameField;
    KeyValuePairWidget  * typeField;
    KeyValuePairWidget  * classField;


    QLabel * name, * type, * cl;

    QVBoxLayout         * mLayout;

};

#endif // DNSQUESTIONENTRY_H
