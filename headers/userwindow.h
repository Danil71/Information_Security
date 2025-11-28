#ifndef USERWINDOW_H
#define USERWINDOW_H

#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class UserManager;

class UserWindow : public QWidget
{
    Q_OBJECT
public:
    UserWindow(UserManager &mgr, const QString &username, const QString &keyPhrase, QWidget *parent = nullptr);
    ~UserWindow();

private slots:
    void onChangePassword();
    void onExit();

private:
    UserManager &manager;
    QString username;
    QString keyPhrase;

    QLabel *lblInfo;
    QLineEdit *editOld;
    QLineEdit *editNew;
    QLineEdit *editConfirm;
    QPushButton *btnChange;
    QPushButton *btnExit;
};

#endif // USERWINDOW_H
