#include "interfaceview.h"
#include "interfacemodel.h"
#include <QHeaderView>

InterfaceView::InterfaceView(QWidget *parent)
{
    QTableView::QTableView(parent);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setEditTriggers(QAbstractItemView::NoEditTriggers);

    setGridStyle(Qt::NoPen);

    headerFont = QFont("Sans Serif", 8);
    recordsFont = QFont("Sans Serif", 6);
    horizontalHeader()->setFont(headerFont);
    horizontalHeader()->setHighlightSections(false);
    verticalHeader()->setHighlightSections(false);
    setFrameShape(QFrame::NoFrame);
    m_model = new InterfaceModel();

    selectedItem = nullptr;

    verticalHeader()->setFont(recordsFont);
    verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    verticalHeader()->setDefaultSectionSize(10);

    connect(this, &InterfaceView::doubleClicked, this, &InterfaceView::setDevice);
    connect(this, &InterfaceView::clicked, this, &InterfaceView::onDeviceSelected);
    connect(m_model, &InterfaceModel::modelResetBegin, this, &InterfaceView::detachModel);
    connect(m_model, &InterfaceModel::modelResetEnd, this, &InterfaceView::attachModel);

    m_model->ReloadAllDevices();




}

InterfaceModel *InterfaceView::getModel()
{
    return m_model;
}

InterfaceView::~InterfaceView() noexcept
{
    setModel(nullptr);
    delete m_model;
}

const InterfaceItem *InterfaceView::getSelectedItem()
{
    return selectedItem;
}

void InterfaceView::attachModel()
{
    setModel(m_model);
    resizeColumnsToContents();
    setSortingEnabled(true);
    connect(selectionModel(), &QItemSelectionModel::currentRowChanged, this, &InterfaceView::setDevice_selection);
}

void InterfaceView::detachModel()
{
    setModel(nullptr);
    selectedItem = nullptr;
    emit deviceInvalidated();
}

void InterfaceView::onDeviceSelected(const QModelIndex &index)
{
    if (index.isValid()) selectedItem = m_model->get(index);
}

void InterfaceView::notifyIfSelected()
{

    if (selectedItem) emit deviceSelected();
}

void InterfaceView::setDevice(const QModelIndex &index)
{
    if (index.isValid())
    {
        selectedItem = m_model->get(index);
    }

    if (selectedItem) emit deviceSelected();
}

void InterfaceView::setDevice_selection(const QModelIndex &current, const QModelIndex &previous)
{
    onDeviceSelected(current);
}
