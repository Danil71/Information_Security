#ifndef USERMANAGER_H
#define USERMANAGER_H

#include <QString>
#include <QList>
#include <QSqlDatabase>
#include <QDate>
#include <optional>

struct UserRecord {
    QString username;
    QString passwordHash;
    bool blocked;
    int minLength;
    int expirationMonths;
    bool restrictionsEnabled;
    QDate lastChange;
};

class UserManager {
private:
    QString encFile;
    QString tempFile;
    QSqlDatabase db;

public:
    UserManager(QString encFilePath);
    ~UserManager();

    bool open(const QString &keyPhrase);
    void closeAndSave(const QString &keyPhrase);

    // user operations
    bool login(const QString &u, const QString &pass);
    QList<UserRecord> getUsers();

    bool addUser(QString name);
    bool deleteUser(QString name);
    bool setPassword(QString name, QString newPass);
    bool blockUser(QString name, bool status);
    bool setMinLength(QString name, int value);
    bool setExpiration(QString name, int months);
    bool setRestrictions(QString name, bool enabled);
    std::optional<UserRecord> getUser(QString name);

    bool ensureAdminExists();
};

#endif
