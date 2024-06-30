#include "keyvaluepairwidget.h"

KeyValuePairWidget::KeyValuePairWidget(const QString &keyname, QWidget *widget, QWidget * parent) : QWidget(parent)
{
    order = new QHBoxLayout();
    name = new QLabel();
    name->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    Put(keyname, widget);
    Commit();
    setLayout(order);
}

KeyValuePairWidget::KeyValuePairWidget(QWidget *parent)
    : QWidget{parent}
{
    order = new QHBoxLayout();
    setLayout(order);
    name = new QLabel();
    name->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    value = nullptr;
}

KeyValuePairWidget::KeyValuePairWidget(KeyValuePairWidget & other)
{
    this->name = other.name;
    this->value = other.value;
    this->order = other.order;
}

void KeyValuePairWidget::Put(const QString & keyName, QWidget * value)
{
    this->name->setText(keyName);
    this->value = value;
}

void KeyValuePairWidget::Commit(void)
{
    order->addWidget(name);
    order->addWidget(value);
}

KeyValuePairWidget::~KeyValuePairWidget()
{
    delete name;
    delete value;
    delete order;
}
