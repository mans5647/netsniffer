#include "dnsquestionentry.h"


DnsQuestionEntry::DnsQuestionEntry(const DnsQuestion &question)
{
    QWidget::QWidget(nullptr);


    nameField = new KeyValuePairWidget{};
    typeField = new KeyValuePairWidget{};
    classField = new KeyValuePairWidget{};


    QLabel * t1 = nameField->getKey();
    QLabel * t2 = typeField->getKey();
    QLabel * t3 = classField->getKey();


    name =  new  QLabel{};
    type =  new  QLabel{};
    cl =    new  QLabel{};


    name->setText(question.name.constData());
    type->setText(QString("%1").arg(question.type));
    cl->setText(QString("%1").arg(question.cl_name));

    nameField->Put(tr("Имя домена:"), name);
    typeField->Put(tr("Тип:"), type);
    classField->Put(tr("Класс:"), cl);


    auto width_1 = t1->fontMetrics().horizontalAdvance(t1->text());
    auto width_2 = t2->fontMetrics().horizontalAdvance(t2->text());
    auto width_3 = t3->fontMetrics().horizontalAdvance(t3->text());


    t1->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    t2->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    t3->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    t1->setMinimumWidth(width_1);
    t2->setMinimumWidth(width_2);
    t3->setMinimumWidth(width_3);

    nameField->Commit();
    typeField->Commit();
    classField->Commit();


    mLayout = new QVBoxLayout{};

    mLayout->addWidget(nameField);
    mLayout->addWidget(typeField);
    mLayout->addWidget(classField);

    setLayout(mLayout);
}

DnsQuestionEntry::~DnsQuestionEntry()
{
    delete nameField;
    delete typeField;
    delete classField;

    delete mLayout;
}
