#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QWidget>
#include <QEventLoop>

class QLabel;
class QLineEdit;
class QPushButton;
class UserManager;

class LoginWindow : public QWidget
{
    Q_OBJECT
public:
    explicit LoginWindow(UserManager &mgr, const QString &keyPhrase, QWidget *parent = nullptr);
    ~LoginWindow();

    // modal-like exec
    bool exec();
    QString getUsername() const { return username; }

private slots:
    void onLoginClicked();
    void onCancelClicked();

private:
    UserManager &manager;
    QString keyPhrase;
    QEventLoop loop;
    bool accepted = false;
    QString username, password;

    // UI
    QLabel *lblUser;
    QLabel *lblPass;
    QLineEdit *editUser;
    QLineEdit *editPass;
    QPushButton *btnLogin;
    QPushButton *btnCancel;
};

#endif // LOGINWINDOW_H
