#include "hexview.h"


HexView::HexView()
{
    init();
}

void HexView::init()
{
    setBackgroundRole(QPalette::Base);
    setMinimumSize(QSize(400, QWIDGETSIZE_MAX));
}
