#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QWidget>
#include <QEventLoop>
#include <QCloseEvent>

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

    bool exec();
    QString getUsername() const { return username; }
    QString getPassword() const { return password; }

private slots:
    void closeEvent(QCloseEvent *event) override;
    void onLoginClicked();
    void onCancelClicked();

private:
    int attempts = 0;
    UserManager &manager;
    QString keyPhrase;
    QEventLoop loop;
    bool accepted = false;
    QString username, password;

    QLabel *lblUser;
    QLabel *lblPass;
    QLineEdit *editUser;
    QLineEdit *editPass;
    QPushButton *btnLogin;
    QPushButton *btnCancel;
};

#endif // LOGINWINDOW_H
