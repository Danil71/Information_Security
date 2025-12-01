#include "headers/loginwindow.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include "headers/usermanager.h"

LoginWindow::LoginWindow(UserManager &mgr, const QString &keyPhrase_, QWidget *parent)
    : QWidget(parent), manager(mgr), keyPhrase(keyPhrase_)
{
    setWindowTitle("Вход");

    lblUser = new QLabel("Имя пользователя:");
    lblPass = new QLabel("Пароль:");

    editUser = new QLineEdit();
    editPass = new QLineEdit();
    editPass->setEchoMode(QLineEdit::Password);

    btnLogin = new QPushButton("Войти");
    btnCancel = new QPushButton("Отмена");

    connect(btnLogin, &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
    connect(btnCancel, &QPushButton::clicked, this, &LoginWindow::onCancelClicked);

    QHBoxLayout *hb1 = new QHBoxLayout();
    hb1->addWidget(lblUser);
    hb1->addWidget(editUser);

    QHBoxLayout *hb2 = new QHBoxLayout();
    hb2->addWidget(lblPass);
    hb2->addWidget(editPass);

    QHBoxLayout *hbButtons = new QHBoxLayout();
    hbButtons->addStretch();
    hbButtons->addWidget(btnLogin);
    hbButtons->addWidget(btnCancel);

    QVBoxLayout *vb = new QVBoxLayout();
    vb->addLayout(hb1);
    vb->addLayout(hb2);
    vb->addLayout(hbButtons);

    setLayout(vb);
    setFixedSize(400,140);
}

LoginWindow::~LoginWindow(){}

bool LoginWindow::exec()
{
    this->show();
    loop.exec();
    this->hide();
    return accepted;
}

void LoginWindow::onLoginClicked()
{
    QString u = editUser->text().trimmed();
    QString p = editPass->text();
    if (u.isEmpty()) {
        QMessageBox::warning(this,"Ошибка","Введите имя пользователя");
        return;
    }

    // try login
    if (!manager.getUser(u)) {
        auto res = QMessageBox::question(this, "Пользователь не найден", "Повторить ввод?");
        if (res == QMessageBox::Yes) return;
        else { accepted = false; loop.quit(); return; }
    }

    if (manager.getUser(u)->blocked) {
        QMessageBox::critical(this,"Доступ запрещён","Этот пользователь заблокирован администратором!");
        loop.quit();
        return;
    }

    if (manager.login(u,p)) {
        username = u;
        password = p;
        accepted = true;
        loop.quit();
    } else {
        attempts++;

        if (attempts >= 3) {
            QMessageBox::critical(this,"Ошибка","Количество попыток исчерпано. Приложение будет закрыто.");
            loop.quit(); // мгновенное завершение работы
            return;
        }

        QMessageBox::warning(
            this,
            "Ошибка",
            "Неверный пароль!\nПопыток осталось: " + QString::number(3 - attempts)
            );
    }
}

void LoginWindow::onCancelClicked()
{
    accepted = false;
    loop.quit();
}

void LoginWindow::closeEvent(QCloseEvent *event)
{
    manager.closeAndSave(keyPhrase);
    event->accept();
}
