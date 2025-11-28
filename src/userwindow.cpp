#include "headers/userwindow.h"
#include "headers/usermanager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QInputDialog>

UserWindow::UserWindow(UserManager &mgr, const QString &username_, const QString &keyPhrase_, QWidget *parent)
    : QWidget(parent), manager(mgr), username(username_), keyPhrase(keyPhrase_)
{
    setWindowTitle("Пользователь: " + username);
    resize(400,220);

    lblInfo = new QLabel("Смена пароля для " + username);

    QLabel *lOld = new QLabel("Старый пароль:");
    editOld = new QLineEdit();
    editOld->setEchoMode(QLineEdit::Password);

    QLabel *lNew = new QLabel("Новый пароль:");
    editNew = new QLineEdit();
    editNew->setEchoMode(QLineEdit::Password);

    QLabel *lConfirm = new QLabel("Подтверждение:");
    editConfirm = new QLineEdit();
    editConfirm->setEchoMode(QLineEdit::Password);

    btnChange = new QPushButton("Сменить");
    btnExit = new QPushButton("Выход");

    connect(btnChange, &QPushButton::clicked, this, &UserWindow::onChangePassword);
    connect(btnExit, &QPushButton::clicked, this, &UserWindow::onExit);

    QVBoxLayout *vb = new QVBoxLayout();
    vb->addWidget(lblInfo);

    QHBoxLayout *hb1 = new QHBoxLayout();
    hb1->addWidget(lOld); hb1->addWidget(editOld);
    vb->addLayout(hb1);

    QHBoxLayout *hb2 = new QHBoxLayout();
    hb2->addWidget(lNew); hb2->addWidget(editNew);
    vb->addLayout(hb2);

    QHBoxLayout *hb3 = new QHBoxLayout();
    hb3->addWidget(lConfirm); hb3->addWidget(editConfirm);
    vb->addLayout(hb3);

    QHBoxLayout *hbButtons = new QHBoxLayout();
    hbButtons->addStretch();
    hbButtons->addWidget(btnChange);
    hbButtons->addWidget(btnExit);
    vb->addLayout(hbButtons);

    setLayout(vb);
}

UserWindow::~UserWindow(){}

void UserWindow::onChangePassword()
{
    QString oldp = editOld->text();
    QString newp = editNew->text();
    QString conf = editConfirm->text();

    if (!manager.login(username, oldp)) {
        QMessageBox::warning(this,"Ошибка","Неверный старый пароль");
        return;
    }
    if (newp != conf) {
        QMessageBox::warning(this,"Ошибка","Пароли не совпадают");
        return;
    }
    // if restrictions enabled
    auto u = manager.getUser(username);
    if (u && u->restrictionsEnabled) {
        bool hasDigit=false, hasArith=false;
        for (auto c : newp.toStdString()) {
            if (isdigit((unsigned char)c)) hasDigit=true;
            if (c=='+'||c=='-'||c=='*'||c=='/') hasArith=true;
        }
        if (!hasDigit || !hasArith) {
            QMessageBox::warning(this,"Ошибка","Пароль не соответствует ограничениям варианта 23 (требуются цифры и знаки + - * /)");
            return;
        }
    }
    if (!manager.setPassword(username, newp)) {
        QMessageBox::warning(this,"Ошибка","Не удалось сменить пароль");
        return;
    }
    QMessageBox::information(this,"OK","Пароль успешно изменён");
}

void UserWindow::onExit()
{
    // request key to save DB
    bool ok=false;
    QString kp = QInputDialog::getText(this,"Ключ шифрования","Введите ключ шифрования для сохранения:", QLineEdit::Password,"",&ok);
    if (!ok) return;
    manager.closeAndSave(kp);
    close();
}
