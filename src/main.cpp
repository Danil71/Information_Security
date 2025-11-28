#include <QApplication>
#include <QMessageBox>
#include <QInputDialog>
#include <QLineEdit>
#include "headers/usermanager.h"
#include "headers/loginwindow.h"
#include "headers/adminwindow.h"
#include "headers/userwindow.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QString encPath = "users.enc";

    // Ввод парольной фразы (ключ)
    // Для простоты — используем QInputDialog здесь
    bool ok=false;
    QString key = QInputDialog::getText(nullptr,"Ключ шифрования","Введите ключ шифрования:", QLineEdit::Password,"",&ok);
    if (!ok) return 0;

    UserManager manager(encPath);
    if (!manager.open(key)) {
        QMessageBox::critical(nullptr, "Ошибка", "Не удалось расшифровать файл. Проверьте ключ.");
        return 0;
    }

    // Показываем окно входа
    LoginWindow loginWnd(manager, key);
    if (!loginWnd.exec()) {
        // user cancelled
        manager.closeAndSave(key);
        return 0;
    }
    QString user = loginWnd.getUsername();

    if (user == "ADMIN") {
        AdminWindow w(manager, key);
        w.show();
        int res = a.exec();
        // on exit ensure saved if not yet
        // manager.closeAndSave(key); // admin window asks for key before saving
        return res;
    } else {
        UserWindow w(manager, user, key);
        w.show();
        return a.exec();
    }
}
