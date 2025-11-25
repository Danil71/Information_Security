#include "headers/mainwindow.h"

#include <QApplication>
#include <QMessageBox>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QString dbFile = "users.enc"; // зашифрованная база

    // === 1) запрашиваем ключ шифрования ===
    LoginDialog keyDlg(true);  // режим = запрос ключа
    if (!keyDlg.exec()) return 0;

    QString key = keyDlg.getPassword();
    UserManager manager(dbFile);

    if (!manager.open(key))
    {
        QMessageBox::critical(nullptr,"Ошибка","Файл не расшифрован. Неверный ключ.");
        return 0;
    }

    // === 2) вход пользователя ===
    LoginDialog login;
    if (!login.exec()){ manager.closeAndSave(key); return 0; }

    QString user = login.getUsername();
    QString pass = login.getPassword();

    if (!manager.login(user,pass))
    {
        QMessageBox::warning(nullptr,"Ошибка","Неверный пароль");
        return 0;
    }

    // === ADMIN or USER ===
    if (user == "ADMIN") {
        AdminWindow w(manager,key);
        w.show();
        return app.exec();
    } else {
        UserWindow w(manager,user,key);
        w.show();
        return app.exec();
    }
}
