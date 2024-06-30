#include "dnsanswerentry.h"
#include "uihelpers.h"


DnsAnswerEntry::DnsAnswerEntry(const DnsAnswer &answer)
{
    QWidget::QWidget(nullptr);
    name = new QLabel(reinterpret_cast<const char*>(answer.name));
    type = new QLabel(DnsStrType(answer.type));
    cl = new QLabel(DnsStrClass(answer.cl_name));

    auto dt = QDateTime::fromSecsSinceEpoch(answer.ttl);
    auto time = dt.time();


    ttl = new QLabel(time.toString("mm минут ss секунд"));
    len = new QLabel(QString("%1 байт").arg(answer.length));

    data = new QLabel();
    if (answer.type == DNS_TYPE_A)
    {
        char addrbuf[ADDR_V4_BUFLEN_MIN];
        data->setText(FromIPv4Address(addrbuf, ADDR_V4_BUFLEN_MIN, &answer.adata.host_addr.address));
    }

    else if (answer.type == DNS_TYPE_CNAME)
    {
        data->setText(reinterpret_cast<const char*>(answer.adata.cname.data));
    }
    else data->setText("Data");


    nameField = new KeyValuePairWidget(tr("Имя домена:"), name);
    typeField = new KeyValuePairWidget(tr("Тип"), type);
    classField = new KeyValuePairWidget(tr("Класс"), cl);
    ttlField = new KeyValuePairWidget(tr("Валидный:"), ttl);
    lenField = new KeyValuePairWidget(tr("Длина:"), len);
    dataField = new KeyValuePairWidget(tr("Данные:"), data);

    mLayout = new QVBoxLayout();

    mLayout->addWidget(nameField);
    mLayout->addWidget(typeField);
    mLayout->addWidget(classField);
    mLayout->addWidget(ttlField);
    mLayout->addWidget(lenField);
    mLayout->addWidget(dataField);


    setLayout(mLayout);
}

DnsAnswerEntry::~DnsAnswerEntry() noexcept
{
    delete nameField;
    delete typeField;
    delete classField;
    delete ttlField;
    delete lenField;
    delete dataField;
    delete mLayout;
}
