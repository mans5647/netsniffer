#ifndef HEXVIEW_H
#define HEXVIEW_H

#include <QScrollArea>
#include <QByteArray>

class HexView : public QScrollArea
{
public:
    HexView();
    void init();

//    void setData(const QByteArray &);
};

#endif // HEXVIEW_H
