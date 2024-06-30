#ifndef INTERFACEVIEW_H
#define INTERFACEVIEW_H

#include <QWidget>
#include <QTableView>

class InterfaceModel;
class InterfaceItem;
class InterfaceView : public QTableView
{
    Q_OBJECT
public:
    InterfaceView(QWidget * parent = nullptr);
    InterfaceModel *getModel();
    ~InterfaceView() noexcept;

public slots:

    const InterfaceItem * getSelectedItem();
    void notifyIfSelected();
private slots:

    void attachModel();
    void detachModel();
    void onDeviceSelected(const QModelIndex & index);
signals:

    void deviceSelected();
    void deviceInvalidated();
private:
    InterfaceModel * m_model;
    const InterfaceItem * selectedItem;
    QFont headerFont;
    QFont recordsFont;

private slots:
    void setDevice(const QModelIndex & index);
    void setDevice_selection(const QModelIndex & current, const QModelIndex & previous);
};

#endif // INTERFACEVIEW_H
