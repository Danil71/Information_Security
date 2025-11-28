#ifndef ADMINWINDOW_H
#define ADMINWINDOW_H

#include <QWidget>
#include <QTimer>

class QTableWidget;
class QPushButton;
class UserManager;

class AdminWindow : public QWidget
{
    Q_OBJECT
public:
    AdminWindow(UserManager &mgr, const QString &keyPhrase, QWidget *parent = nullptr);
    ~AdminWindow();

private slots:
    void onAddUser();
    void onDeleteUser();
    void onBlockUser();
    void onUnblockUser();
    void onChangePassword();
    void onSaveExit();

private:
    UserManager &manager;
    QString keyPhrase;

    QTableWidget *table;
    QPushButton *btnAdd, *btnDelete, *btnBlock, *btnUnblock, *btnChangePass, *btnSaveExit, *btnRefresh;
    void fillTable();
    QString selectedUser() const;
};

#endif // ADMINWINDOW_H
