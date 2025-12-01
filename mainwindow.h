#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFile>

class QPushButton;
class QLabel;
class QLineEdit;
class QTextEdit;
class QRadioButton;
class QProgressBar;
class QGroupBox;
class QCheckBox;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void chooseSource();
    void chooseDestination();
    void choosePasswordFile();
    void onModeChanged();
    void processFile(); // encrypt/decrypt
private:
    void setupUi();
    bool readPassword(std::vector<uint8_t>& out);
    QByteArray deriveKeyFromPassword(const QByteArray& pass); // MD5 -> first 8 bytes
    bool encryptStream(QFile &inFile, QFile &outFile, const std::array<uint8_t,8>& key);
    bool decryptStream(QFile &inFile, QFile &outFile, const std::array<uint8_t,8>& key);

    // widgets
    QLabel *lblStudent;
    QLabel *lblVariant;
    QTextEdit *txtAlgorithm;
    QLineEdit *leSource;
    QLineEdit *leDest;
    QPushButton *btnSource;
    QPushButton *btnDest;
    QRadioButton *rbEncrypt;
    QRadioButton *rbDecrypt;
    QRadioButton *rbPassKeyboard;
    QRadioButton *rbPassFile;
    QLineEdit *lePassword;
    QPushButton *btnPassFile;
    QPushButton *btnProcess;
    QProgressBar *progress;

    QString sourcePath;
    QString destPath;
    QString passFilePath;
};

#endif // MAINWINDOW_H
