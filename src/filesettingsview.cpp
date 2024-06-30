#include "filesettingsview.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QGroupBox>
#include <QFileDialog>
#include <QFile>
#include <QLabel>
#include <QMessageBox>
#include <QSpacerItem>
#include <QDir>
#include <QFileDialog>

FileSettingsView::FileSettingsView(QWidget * parent) : QWidget(parent)
{
    section_general =       new QGroupBox(QObject::tr("Общие настройки"));
    __layout_gbox =         new QVBoxLayout();

    fileNameEdit =          new QLineEdit;

    fileNameEdit->setFixedWidth(100 * 2);
    useCustomFileName =     new QRadioButton(QObject::tr("Пользовательское имя"));
    useDefaultFileName =    new QRadioButton(QObject::tr("Имя по умолчанию"));
    useDefaultFileName->setFixedWidth(useDefaultFileName->width());
    filename_preview =      new QLabel();
    __layout_name_checks_preview = new QHBoxLayout();

    __layout_name_checks_preview->addWidget(fileNameEdit);
    __layout_name_checks_preview->addWidget(useCustomFileName);
    __layout_name_checks_preview->addWidget(useDefaultFileName);
    __layout_name_checks_preview->addWidget(filename_preview);

    right_shrink = new QSpacerItem(100, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

    __layout_name_checks_preview->addSpacerItem(right_shrink);

    __layout_gbox->addLayout(__layout_name_checks_preview);

    fileLocationEdit =  new QLineEdit();
    btn_setLocation =   new QPushButton(QObject::tr("Выбрать папку ..."));

    __layout_loc =      new QHBoxLayout();

    __layout_loc->addWidget(fileLocationEdit);
    __layout_loc->addWidget(btn_setLocation);

    __layout_gbox->addLayout(__layout_loc);

    space = new QSpacerItem(20, 200, QSizePolicy::Expanding, QSizePolicy::Minimum);
    __layout_gbox->addSpacerItem(space);

    section_general->setLayout(__layout_gbox);
    filename_default_name = QObject::tr(DEFAULT_NAME_FMT_HUMAN);
    useDefaultFileName->setChecked(true);
    fileNameEdit->setEnabled(false);
    filename_preview->setText(PrettyDefaultName());
    filename_preview->setAlignment(Qt::AlignCenter | Qt::AlignLeft);
    m_layout =          new QVBoxLayout();
    m_layout->addWidget(section_general);

    setLayout(m_layout);

    mode = Special;
    m_save_dir = new QDir();
    connect(this, &FileSettingsView::noSuchDirectory, this, &FileSettingsView::notify_invalid_dir);
    connect(this, &FileSettingsView::invalidCharactersEntered, this, &FileSettingsView::createWarnings);
    connect(fileNameEdit, &QLineEdit::returnPressed, this, &FileSettingsView::setFilenameFromEdit);
    connect(fileLocationEdit, &QLineEdit::returnPressed, this, &FileSettingsView::checkEnteredDir);
    connect(fileNameEdit, &QLineEdit::textChanged, this, &FileSettingsView::setFilename__custom);
    connect(useCustomFileName, &QRadioButton::clicked, this, &FileSettingsView::OnClicked_custom);
    connect(useDefaultFileName, &QRadioButton::clicked, this, &FileSettingsView::OnClicked_default);
    connect(btn_setLocation, &QPushButton::clicked, this, &FileSettingsView::handleDirSelection);
    m_dir_choose = new QFileDialog();


#ifdef DEBUG
    m_save_dir->setCurrent(FILE_PATH_DEBUG);
#else
    m_save_dir->setCurrent(FILE_PATH_RELEASE);
#endif
    m_save_dir->makeAbsolute();
    fileLocationEdit->setText(m_save_dir->path());
    m_dir_choose->setDirectory(*m_save_dir);
    m_dir_choose->setFileMode(QFileDialog::Directory);
    m_dir_choose->setWindowTitle(QObject::tr("Выберите временную папку ..."));

    connect(m_dir_choose, &QFileDialog::directoryEntered, this, &FileSettingsView::setSaveDir);
}

QString FileSettingsView::getFilename() const
{
    return getMode() == Custom ? rname : filename;
}

QString FileSettingsView::getLocation() const
{
    return m_save_dir->path();
}

FileNameMode FileSettingsView::getMode() const
{
    return mode;
}

void FileSettingsView::setFilename__custom(const QString &name)
{
    auto index = name.indexOf(" \t");
    if (index != -1)
    {
        emit invalidCharactersEntered();
    }
    else if (name.isEmpty())
    {
        filename = QString();
    }
    else
    {
        filename = name + QString(".pcap");
    }
    filename_preview->setText(PrettyName());
}

void FileSettingsView::setFileName__default()
{

}

QString FileSettingsView::formattedName()
{
    return filename;
}

QString FileSettingsView::getPrettyName()
{
    return PrettyName();
}

void FileSettingsView::setFilenameFromEdit()
{
    auto name = fileNameEdit->text();
    setFilename__custom(name);
}

void FileSettingsView::SetDefaultName(const QString &dateText, const QString &adapterName)
{
    filename = QString(DEFAULT_NAME_FMT).arg(dateText, adapterName);
}

void FileSettingsView::notify_invalid_dir()
{
    QMessageBox * box = new QMessageBox();
    box->setWindowTitle(QObject::tr("Такой папки не существует"));
    box->setText(QObject::tr("Введена недействительная папка для сохранения"));
    box->show();
}

void FileSettingsView::checkEnteredDir()
{
    const QString path = fileLocationEdit->text();
    if (!path.isEmpty())
    {
        m_save_dir->setPath(path);
        if (!m_save_dir->exists())
        {
            emit noSuchDirectory();
        }
        else
            setSaveDir(m_save_dir->path());
    }
    else fileLocationEdit->setPlaceholderText(m_save_dir->path());
}

void FileSettingsView::setSaveDir(const QString &directory)
{
    m_save_dir->cd(directory);
    m_save_dir->makeAbsolute();
    fileLocationEdit->setText(m_save_dir->path());
}

void FileSettingsView::handleDirSelection()
{
    int result = m_dir_choose->exec();
    if (result)
    {
        setSaveDir(m_dir_choose->directory().path());
    }
}

void FileSettingsView::createWarnings()
{
    QMessageBox msgBox;
    msgBox.setText(QObject::tr("Недопустимые символы для имени"));
    msgBox.exec();
}

void FileSettingsView::OnClicked_custom(bool clicked)
{
    if (clicked)
    {
        mode = Custom;
        filename_preview->setText(PrettyName());
        fileNameEdit->setEnabled(true);
    }
    emit modeChanged();
}

void FileSettingsView::OnClicked_default(bool clicked)
{
    if (clicked)
    {
        mode = Special;
        filename_preview->setText(PrettyDefaultName());
        fileNameEdit->setEnabled(false);
    }
    emit modeChanged();
}

QString FileSettingsView::PrettyName()
{
    if (filename.endsWith(".pcap"))
    {
        filename.erase(filename.begin() + filename.indexOf(".pcap"), filename.end());
        rname = filename + QString(".pcap");
    }

    if (getMode() == Custom) return QString(FMT_PREVIEW).arg(rname);

    return QString(FMT_PREVIEW).arg(filename.size() > 0 ? filename + QString(".pcap") : "(пусто)");
}

QString FileSettingsView::PrettyDefaultName()
{
    return QString(FMT_DEFAULT_PRETTY).arg(filename_default_name);
}
