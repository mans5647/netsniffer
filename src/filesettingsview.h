#ifndef FILESETTINGSVIEW_H
#define FILESETTINGSVIEW_H

class QVBoxLayout;
class QHBoxLayout;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QGroupBox;
class QFile;
class QLabel;
class QSpacerItem;
class QDir;
class QFileDialog;

#include <QWidget>
#include <QString>

#define DEFAULT_NAME_FMT "%1_%2.pcap"
#define DEFAULT_NAME_FMT_HUMAN "дата_имяадаптера.[pcap]"
#define FMT_PREVIEW "Предпросмотр: %1"
#define FMT_DEFAULT_PRETTY "Формат: %1"

#define FILE_PATH_DEBUG ".\\"
#define FILE_PATH_RELEASE "..\\Saved\\"

#define DEBUG 1
enum FileNameMode
{
    Custom,
    Special
};

class FileSettingsView : public QWidget
{
    Q_OBJECT
public:
    FileSettingsView(QWidget * parent = nullptr);
    QString getFilename() const;
    QString getLocation() const;
    FileNameMode getMode() const;
private:

    QVBoxLayout     * m_layout;
    QVBoxLayout     * __layout_gbox; // group box layout
    QHBoxLayout     * __layout_name_checks_preview; // radio buttons and preview name layout
    QHBoxLayout     * __layout_loc; // location layout
    QGroupBox       * section_general;
    QLineEdit       * fileNameEdit;
    QLineEdit       * fileLocationEdit;
    QRadioButton    * useCustomFileName;
    QRadioButton    * useDefaultFileName;
    QPushButton     * btn_setLocation;
    QLabel          * filename_preview;
    QString         filename;
    QString         location;
    QString         filename_default_name;
    QString         rname;
    QSpacerItem     * space;
    QSpacerItem     * right_shrink;
    FileNameMode mode;
    QDir            * m_save_dir;
    QFileDialog     * m_dir_choose; // file dialog used for select directory for process pcap saving

    void setFilename__custom(const QString & name);
    void setFileName__default();


signals:
    void noSuchDirectory();
    void modeChanged();
    void invalidCharactersEntered();

public slots:
    QString formattedName();
    QString getPrettyName();
    void SetDefaultName(const QString & dateText, const QString & adapterName);

private slots:
    void setFilenameFromEdit();
    void notify_invalid_dir();
    void checkEnteredDir();
    void setSaveDir(const QString & directory);
    void handleDirSelection();
    void createWarnings();
    void OnClicked_custom(bool clicked);
    void OnClicked_default(bool clicked);
    QString PrettyName();
    QString PrettyDefaultName();
};

#endif // FILESETTINGSVIEW_H
