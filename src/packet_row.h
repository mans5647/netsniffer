#ifndef PACKET_ROW_H
#define PACKET_ROW_H

#include <QObject>
#include <QWidget>
#include <QTableWidgetItem>
#include "protocolparser.h"

class packet_row
{
public:
    packet_row(const void*);


    packet_row & operator=(packet_row &&) noexcept;
    QTableWidgetItem * record[7];
private:
    void ConstructRow();

private:
#define COLUMN_COUNT 7
#define COLUMN_NO           0
#define COLUMN_DIFF_TIME    1
#define COLUMN_SRC          2
#define COLUMN_DST          3
#define COLUMN_PROTO        4
#define COLUMN_LEN          5
#define COLUMN_INFO         6
    FrameInfo * frame_un;
};


QTableWidgetItem * AppendTableRow(packet_row &, QTableWidget*, int); // new record will be written into end of table
void DeleteTableRow(int); // delete specific row

#endif // PACKET_ROW_H
