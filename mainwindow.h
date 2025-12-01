#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QFileDialog>
#include <QCryptographicHash>
#include <QVBoxLayout>
#include <QGroupBox>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

private slots:
    void chooseFile();
    void calcHash();
    void saveHash();

private:
    // элементы формы
    QLineEdit *editFio;
    QLineEdit *editGroup;
    QLineEdit *editVariant;
    QTextEdit *infoText;

    QLineEdit *editFilePath;
    QLineEdit *editHash;
    QLineEdit *ourEditHash;

    QPushButton *btnChooseFile;
    QPushButton *btnHash;
    QPushButton *btnSave;
};

#endif // MAINWINDOW_H
