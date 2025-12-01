#include "headers/adminwindow.h"
#include "headers/usermanager.h"
#include <QTableWidget>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QInputDialog>
#include <QMessageBox>
#include <QHeaderView>

AdminWindow::AdminWindow(UserManager &mgr, const QString &keyPhrase_, QWidget *parent)
    : QWidget(parent), manager(mgr), keyPhrase(keyPhrase_)
{
    setWindowTitle("Admin — управление пользователями");
    resize(800,400);

    menu = new QMenuBar(this);

    QMenu *menuHelp = menu->addMenu("Справка");

    QAction *actAbout = new QAction("О программе", this);
    menuHelp->addAction(actAbout);

    connect(actAbout, &QAction::triggered, this, &AdminWindow::showAbout);

    table = new QTableWidget();
    table->setColumnCount(5);
    table->setHorizontalHeaderLabels(QStringList() << "Имя" << "Блок" << "Мин.длина" << "Срок(мес)" << "Ограничения");
    table->horizontalHeader()->setStretchLastSection(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setEditTriggers(
        QAbstractItemView::DoubleClicked
        );

    btnAdd = new QPushButton("Добавить");
    btnDelete = new QPushButton("Удалить");
    btnBlock = new QPushButton("Блокировать");
    btnUnblock = new QPushButton("Разблокировать");
    btnRefresh = new QPushButton("Обновить");
    btnChangePass = new QPushButton("Сменить пароль");

    btnSaveExit = new QPushButton("Сохранить и выйти");

    connect(btnAdd, &QPushButton::clicked, this, &AdminWindow::onAddUser);
    connect(btnDelete, &QPushButton::clicked, this, &AdminWindow::onDeleteUser);
    connect(btnBlock, &QPushButton::clicked, this, &AdminWindow::onBlockUser);
    connect(btnUnblock, &QPushButton::clicked, this, &AdminWindow::onUnblockUser);
    connect(btnChangePass, &QPushButton::clicked, this, &AdminWindow::onChangePassword);
    connect(btnSaveExit, &QPushButton::clicked, this, &AdminWindow::onSaveExit);
    connect(btnRefresh, &QPushButton::clicked, this, &AdminWindow::fillTable);
    connect(table, &QTableWidget::cellChanged, this, &AdminWindow::onCellEdited);
    connect(table, &QTableWidget::cellDoubleClicked, this, &AdminWindow::onRestrictionsDoubleClicked);

    QHBoxLayout *hb = new QHBoxLayout();
    hb->addWidget(btnAdd);
    hb->addWidget(btnDelete);
    hb->addWidget(btnBlock);
    hb->addWidget(btnUnblock);
    hb->addWidget(btnChangePass);
    hb->addWidget(btnRefresh);
    hb->addStretch();
    hb->addWidget(btnSaveExit);

    QVBoxLayout *vb = new QVBoxLayout();
    vb->setMenuBar(menu);
    vb->addWidget(table);
    vb->addLayout(hb);
    setLayout(vb);

    fillTable();
}

AdminWindow::~AdminWindow() {}

void AdminWindow::fillTable()
{
    table->clearContents();
    auto users = manager.getUsers();
    table->setRowCount(users.size());
    int r = 0;
    for (auto &u : users) {
        table->setItem(r,0, new QTableWidgetItem(u.username));
        table->setItem(r,1, new QTableWidgetItem(u.blocked ? "Да" : "Нет"));
        table->setItem(r,2, new QTableWidgetItem(QString::number(u.minLength)));
        table->setItem(r,3, new QTableWidgetItem(QString::number(u.expirationMonths)));
        table->setItem(r,4, new QTableWidgetItem(u.restrictionsEnabled ? "Да" : "Нет"));
        r++;
    }
}

QString AdminWindow::selectedUser() const
{
    auto sel = table->selectedItems();
    if (sel.isEmpty()) return QString();
    int row = table->row(sel.first());
    auto it = table->item(row,0);
    if (!it) return QString();
    return it->text();
}

void AdminWindow::onAddUser()
{
    bool ok=false;
    QString name = QInputDialog::getText(this,"Добавить пользователя","Имя пользователя:", QLineEdit::Normal, "", &ok);
    if (!ok || name.trimmed().isEmpty()) return;
    if (!manager.addUser(name)) QMessageBox::warning(this,"Ошибка","Не удалось добавить пользователя");
    fillTable();
}

void AdminWindow::onDeleteUser()
{
    QString name = selectedUser();
    if (name.isEmpty()) { QMessageBox::warning(this,"Ошибка","Выберите пользователя"); return; }
    if (name=="ADMIN") { QMessageBox::warning(this,"Ошибка","Нельзя удалить ADMIN"); return; }
    if (QMessageBox::question(this,"Удалить","Удалить "+name+"?") == QMessageBox::Yes) {
        if (!manager.deleteUser(name)) QMessageBox::warning(this,"Ошибка","Не удалось удалить");
    }
    fillTable();
}

void AdminWindow::onBlockUser()
{
    QString name = selectedUser();
    if (name.isEmpty()) { QMessageBox::warning(this,"Ошибка","Выберите пользователя"); return; }
    if (!manager.blockUser(name,true)) QMessageBox::warning(this,"Ошибка","Не удалось заблокировать");
    fillTable();
}

void AdminWindow::onCellEdited(int row, int col)
{
    disconnect(table, &QTableWidget::cellChanged,
               this, &AdminWindow::onCellEdited);

    QString user = table->item(row,0)->text();
    if (col == 2) {
        bool ok; int val = table->item(row,col)->text().toInt(&ok);
        if (!ok || val < 0 || val > 200 || !manager.setMinLength(user,val)) {
            QMessageBox::warning(this,"Ошибка","Мин. длина 0-200");
        }
    }

    else if (col == 3) {
        bool ok; int months = table->item(row,col)->text().toInt(&ok);
        if (!ok || months < 0 || months > 60 || !manager.setExpiration(user,months)) {
            QMessageBox::warning(this,"Ошибка","Срок 0-60 месяцев");
        }
    }

    fillTable();

    connect(table, &QTableWidget::cellChanged,
            this, &AdminWindow::onCellEdited);

}

void AdminWindow::showAbout()
{
    QMessageBox msg(this);
    msg.setWindowTitle("О программе");
    msg.setIcon(QMessageBox::Information);

    msg.setText(
        "<div align='center'>"
        "<b>Лабораторная 1</b><br>"
        "Автор: Путинцев Даниил Максимович<br>"
        "<b>Вариант:</b> 23<br><br>"
        "<b>Индивидуальное задание:</b><br>"
        "Ограничение на выбираемые пароли: наличие цифр и знаков арифметики (+ - * /)<br>"
        "Используемый режим шифрования DES: <b>CFB</b><br>"
        "Добавление к ключу случайного значения: <b>Да</b><br>"
        "Используемый алгоритм хеширования паролей: <b>MD5</b><br>"
        );

    msg.setStandardButtons(QMessageBox::Ok);
    msg.exec();
}

void AdminWindow::onRestrictionsDoubleClicked(int row, int col)
{
    if (col != 4) return;

    QString user = table->item(row,0)->text();
    bool curr = (table->item(row,col)->text() == "Да");
    bool next = !curr;

    if(manager.setRestrictions(user,next))
        table->item(row,col)->setText(next ? "Да" : "Нет");
    else
        QMessageBox::warning(this,"Ошибка","Не удалось обновить ограничение");
}

void AdminWindow::onUnblockUser()
{
    QString name = selectedUser();
    if (name.isEmpty()) { QMessageBox::warning(this,"Ошибка","Выберите пользователя"); return; }
    if (!manager.blockUser(name,false)) QMessageBox::warning(this,"Ошибка","Не удалось разблокировать");
    fillTable();
}

void AdminWindow::onChangePassword()
{
    QString name = selectedUser();
    if (name.isEmpty()) { QMessageBox::warning(this,"Ошибка","Выберите пользователя"); return; }

    bool ok=false;
    QString newp = QInputDialog::getText(this,"Смена пароля","Новый пароль для "+name+":", QLineEdit::Password, "", &ok);
    if (!ok) return;
    QString confirm = QInputDialog::getText(this,"Подтверждение","Подтвердите пароль:", QLineEdit::Password, "", &ok);
    if (!ok) return;
    if (newp != confirm) { QMessageBox::warning(this,"Ошибка","Пароли не совпадают"); return; }
    auto u = manager.getUser(name);
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
    if (!manager.setPassword(name,newp)) QMessageBox::warning(this,"Ошибка","Не удалось установить пароль");
    fillTable();
}

void AdminWindow::onSaveExit()
{
    manager.closeAndSave(keyPhrase);
    close();
}

void AdminWindow::closeEvent(QCloseEvent *event)
{
    manager.closeAndSave(keyPhrase);
    event->accept();
}
