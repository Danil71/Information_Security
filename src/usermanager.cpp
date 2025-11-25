#include "headers/usermanager.h"
#include "headers/crypto.h"
#include <QFile>
#include <QSqlQuery>
#include <QSqlError>
#include <QDir>
#include <QDebug>

UserManager::UserManager(QString encPath)
    : encFile(encPath), tempFile("users_temp.sqlite") {}

UserManager::~UserManager() {}

// OPEN:  decrypt users.enc → create temp sqlite DB → load QSqlDatabase
bool UserManager::open(const QString &keyPhrase)
{
    // 1) если нет users.enc — создаём пустую БД и сразу шифруем
    if (!QFile::exists(encFile)) {
        qDebug() << "Encrypted DB not found — creating new.";
        QSqlDatabase temp = QSqlDatabase::addDatabase("QSQLITE","init");
        temp.setDatabaseName(tempFile);
        temp.open();
        temp.exec("CREATE TABLE users("
                  "username TEXT PRIMARY KEY,"
                  "password TEXT,"
                  "blocked INTEGER,"
                  "min_len INTEGER,"
                  "exp INTEGER,"
                  "restr INTEGER,"
                  "last_change TEXT)");
        temp.close();
        QByteArray raw = QFile(tempFile).readAll();
        QFile(encFile).write(encryptWithHeader(keyPhrase,raw));
        QFile(tempFile).remove();
    }

    // 2) читаем и расшифровываем users.enc
    QByteArray enc = QFile(encFile).readAll();
    auto dec = decryptWithHeader(keyPhrase, enc);
    if (!dec) return false; // неверный ключ

    // сохраняем расшифрованную копию во временный sqlite
    QFile f(tempFile);
    f.open(QFile::WriteOnly);
    f.write(*dec);
    f.close();

    // 3) подключаем SQLite
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(tempFile);
    if(!db.open()) return false;

    // 4) гарантируем наличие ADMIN
    return ensureAdminExists();
}

// CLOSE: read sqlite → encrypt → save to users.enc
void UserManager::closeAndSave(const QString &keyPhrase)
{
    if(db.isOpen()) {
        db.close();
        QByteArray raw = QFile(tempFile).readAll();
        QByteArray enc = encryptWithHeader(keyPhrase,raw);

        QFile(encFile).remove();
        QFile(encFile).open(QFile::WriteOnly);
        QFile(encFile).write(enc);
        QFile(encFile).close();

        QFile(tempFile).remove();
    }
}

// Create ADMIN if missing
bool UserManager::ensureAdminExists(){
    QSqlQuery q("SELECT COUNT(*) FROM users WHERE username='ADMIN'");
    q.next();
    if(q.value(0).toInt()==0){
        QSqlQuery c;
        c.prepare("INSERT INTO users VALUES('ADMIN', '',0,0,0,0,:d)");
        c.bindValue(":d",QDate::currentDate().toString(Qt::ISODate));
        return c.exec();
    }
    return true;
}

// LOGIN
bool UserManager::login(const QString &u,const QString &pass)
{
    auto urec = getUser(u);
    if(!urec) return false;
    if(urec->blocked) return false;
    return urec->passwordHash == md5HashHex(pass);
}

// USERS LIST
QList<UserRecord> UserManager::getUsers()
{
    QList<UserRecord> list;
    QSqlQuery q("SELECT * FROM users");
    while(q.next()){
        UserRecord u;
        u.username = q.value(0).toString();
        u.passwordHash = q.value(1).toString();
        u.blocked = q.value(2).toBool();
        u.minLength = q.value(3).toInt();
        u.expirationMonths = q.value(4).toInt();
        u.restrictionsEnabled = q.value(5).toBool();
        u.lastChange = QDate::fromString(q.value(6).toString(),Qt::ISODate);
        list << u;
    }
    return list;
}

// ADD USER
bool UserManager::addUser(QString name)
{
    QSqlQuery q;
    q.prepare("INSERT INTO users VALUES(:u,'',0,0,0,0,:d)");
    q.bindValue(":u",name);
    q.bindValue(":d",QDate::currentDate().toString(Qt::ISODate));
    return q.exec();
}

// DELETE USER
bool UserManager::deleteUser(QString name)
{
    QSqlQuery q;
    q.prepare("DELETE FROM users WHERE username=:u");
    q.bindValue(":u",name);
    return q.exec();
}

// SET PASSWORD — MD5 + дата смены
bool UserManager::setPassword(QString name, QString newPass)
{
    QString hash = md5HashHex(newPass);
    QSqlQuery q;
    q.prepare("UPDATE users SET password=:p, last_change=:d WHERE username=:u");
    q.bindValue(":p",hash);
    q.bindValue(":d",QDate::currentDate().toString(Qt::ISODate));
    q.bindValue(":u",name);
    return q.exec();
}

bool UserManager::blockUser(QString name, bool status)
{
    QSqlQuery q;
    q.prepare("UPDATE users SET blocked=:b WHERE username=:u");
    q.bindValue(":b",status?1:0);
    q.bindValue(":u",name);
    return q.exec();
}

// GET USER
std::optional<UserRecord> UserManager::getUser(QString name)
{
    QSqlQuery q;
    q.prepare("SELECT * FROM users WHERE username=:u");
    q.bindValue(":u",name);
    q.exec();
    if(q.next()){
        UserRecord u;
        u.username=q.value(0).toString();
        u.passwordHash=q.value(1).toString();
        u.blocked=q.value(2).toBool();
        u.minLength=q.value(3).toInt();
        u.expirationMonths=q.value(4).toInt();
        u.restrictionsEnabled=q.value(5).toBool();
        u.lastChange=QDate::fromString(q.value(6).toString(),Qt::ISODate);
        return u;
    }
    return std::nullopt;
}
