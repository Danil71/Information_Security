#ifndef ADMINWINDOW_H
#define ADMINWINDOW_H

#include <QWidget>
#include <QTimer>
#include <QMenuBar>
#include <QCloseEvent>

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
    void closeEvent(QCloseEvent *event) override;
    void showAbout();
    void onAddUser();
    void onDeleteUser();
    void onBlockUser();
    void onUnblockUser();
    void onChangePassword();
    void onSaveExit();
    void onCellEdited(int row, int col);
    void onRestrictionsDoubleClicked(int row, int col);

private:
    UserManager &manager;
    QString keyPhrase;
    QMenuBar *menu;
    QTableWidget *table;
    QPushButton *btnAdd, *btnDelete, *btnBlock, *btnUnblock, *btnChangePass, *btnSaveExit, *btnRefresh;
    void fillTable();
    QString selectedUser() const;
};

#endif // ADMINWINDOW_H
