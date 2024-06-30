#include "pairfield.h"


PairField::PairField(const PairType &record, PairField *parent)
{
    this->record = record;
    this->parent = parent;
}

void PairField::addChild(std::unique_ptr<PairField> &&item)
{
    children.push_back(std::move(item));
}

PairField *PairField::child(int row)
{
    return (row >= 0 && row < childCount()) ? children.at(row).get() : nullptr;
}

int PairField::childCount() const
{
    return children.size();
}

int PairField::columnCount() const
{
    return int(1);
}

PairField::PairType PairField::data(int column) const
{
    return record;
}

int PairField::row() const
{
    return 0;
}

PairField *PairField::parentItem()
{
    return nullptr;
}
