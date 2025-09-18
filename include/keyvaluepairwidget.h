#ifndef KEYVALUEPAIRWIDGET_H
#define KEYVALUEPAIRWIDGET_H

#include <QObject>
#include <QWidget>
#include <QLayout>
#include <QLabel>
#include <QListWidget>
#include <QPair>

class KeyValuePairWidget : public QWidget
{
    Q_OBJECT
public:
    // makes all things in constructor
    explicit KeyValuePairWidget(const QString & keyname, QWidget * widget, QWidget * parent = nullptr);
    // constructs empty key value widget
    explicit KeyValuePairWidget(QWidget *parent = nullptr);


    KeyValuePairWidget(KeyValuePairWidget &);

    void Put(const QString &, QWidget*);
    void Commit(void);
    QLabel* getKey() { return name; }
    const QWidget * getValue() { return value; }

    ~KeyValuePairWidget();

private:

    QLabel * name;
    QWidget * value;
    QHBoxLayout * order;

signals:

};

#endif // KEYVALUEPAIRWIDGET_H
