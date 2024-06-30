#ifndef PAIRFIELD_H
#define PAIRFIELD_H

#include <QString>
#include <QObject>
#include <QWidget>
#include <vector>
#include <memory>

// represents: KEY NAME (string): value (string)
class PairField : public QObject
{
    Q_OBJECT
public:
    using PairType = QPair<QString, QString>;
    explicit PairField(const PairType & record, PairField * parent = nullptr);
    void addChild(std::unique_ptr<PairField> && item);


    PairField *child(int row);
    int childCount() const;
    int columnCount() const;
    PairType data(int column) const;
    int row() const;
    PairField *parentItem();

private:

    std::vector<std::unique_ptr<PairField>> children;
    PairType record;
    PairField * parent;

};

#endif // PAIRFIELD_H
