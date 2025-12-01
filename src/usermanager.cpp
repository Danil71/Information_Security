#include "headers/usermanager.h"
#include "headers/crypto.h"
#include <QFile>
#include <QSqlQuery>
#include <QSqlError>
#include <QDir>
#include <QDebug>
#include <QMessageBox>

UserManager::UserManager(QString encPath)
    : encFile(encPath), tempFile("users_temp.sqlite") {}

UserManager::~UserManager() {}

bool UserManager::open(const QString &keyPhrase)
{
    // Если users.enc ещё нет → создаём SQLite файл
    if (!QFile::exists(encFile))
    {
        qDebug() << "[INFO] encrypted DB not found → NEW created";

        QMessageBox::information(
            nullptr,
            "Создание базы данных",
            "Файл зашифрованной БД отсутствовал.\nСоздан новый файл users.enc."
            );

        // --- создаём SQLite с таблицей ---
        QSqlDatabase init = QSqlDatabase::addDatabase("QSQLITE","init");
        init.setDatabaseName(tempFile);

        if(!init.open()){
            qDebug() << "[FATAL] Can't create SQLite" << init.lastError();
            return false;
        }

        QSqlQuery q(init);
        q.exec("CREATE TABLE users("
               "username TEXT PRIMARY KEY,"
               "password TEXT,"
               "blocked INTEGER,"
               "min_len INTEGER,"
               "exp INTEGER,"
               "restr INTEGER,"
               "last_change TEXT)");

        init.close();
        QSqlDatabase::removeDatabase("init");

        // --- читаем temp.sqlite в память ---
        QFile ftemp(tempFile);
        ftemp.open(QIODevice::ReadOnly);
        QByteArray raw = ftemp.readAll();
        ftemp.close();

        // --- шифруем и создаём users.enc ---
        QFile out(encFile);
        out.open(QIODevice::WriteOnly);
        out.write(encryptWithHeader(keyPhrase, raw));
        out.close();

        QFile(tempFile).remove(); // очищаем, база будет расшифровываться заново
    }

    QFile enc(encFile);
    if(!enc.open(QIODevice::ReadOnly)){
        qDebug()<<"[ERROR] cannot open users.enc";
        return false;
    }

    QByteArray encData = enc.readAll();
    enc.close();

    auto dec = decryptWithHeader(keyPhrase, encData);
    if(dec->isEmpty() || !dec->startsWith("SQLite format 3")){
        qDebug()<<"[FAIL] wrong encryption key";
        return false;
    }

    QFile t(tempFile);
    t.open(QIODevice::WriteOnly);
    t.write(*dec);
    t.close();

    db = QSqlDatabase::addDatabase("QSQLITE","live");
    db.setDatabaseName(tempFile);

    if(!db.open()){
        qDebug()<<"[ERROR] DB open fail" << db.lastError();
        return false;
    }

    ensureAdminExists();
    return true;
}

void UserManager::closeAndSave(const QString &keyPhrase)
{
    if(db.isOpen()){
        db.close();
        QSqlDatabase::removeDatabase("live");

        QFile f(tempFile);
        f.open(QIODevice::ReadOnly);
        QByteArray raw = f.readAll();
        f.close();

        QFile out(encFile);
        out.open(QIODevice::WriteOnly);
        out.write(encryptWithHeader(keyPhrase, raw));
        out.close();

        QFile(tempFile).remove();
        qDebug()<<"[OK] Saved and encrypted ✔";
    }
}

bool UserManager::ensureAdminExists(){
    QSqlQuery q(db);
    q.exec("SELECT COUNT(*) FROM users WHERE username='ADMIN'");
    q.next();

    if(q.value(0).toInt()==0){
        QSqlQuery c(db);
        c.prepare("INSERT INTO users VALUES('ADMIN','d41d8cd98f00b204e9800998ecf8427e',0,0,0,0,:d)");
        c.bindValue(":d",QDate::currentDate().toString(Qt::ISODate));
        return c.exec();
    }
    return true;
}

bool UserManager::login(const QString &u,const QString &pass){
    auto R=getUser(u);
    if(!R || R->blocked) return false;
    return R->passwordHash == md5HashHex(pass);
}

QList<UserRecord> UserManager::getUsers(){
    QList<UserRecord> L;
    QSqlQuery q("SELECT * FROM users", db);
    while(q.next()){
        UserRecord u;
        u.username=q.value(0).toString();
        u.passwordHash=q.value(1).toString();
        u.blocked=q.value(2).toBool();
        u.minLength=q.value(3).toInt();
        u.expirationMonths=q.value(4).toInt();
        u.restrictionsEnabled=q.value(5).toBool();
        u.lastChange=QDate::fromString(q.value(6).toString(),Qt::ISODate);
        L<<u;
    }
    return L;
}

bool UserManager::addUser(QString name){
    QSqlQuery q(db);
    q.prepare("INSERT INTO users VALUES(:u,'',0,0,0,1,:d)");
    q.bindValue(":u",name);
    q.bindValue(":d",QDate::currentDate().toString(Qt::ISODate));
    return q.exec();
}

bool UserManager::deleteUser(QString name){
    QSqlQuery q(db);
    q.prepare("DELETE FROM users WHERE username=:u");
    q.bindValue(":u",name);
    return q.exec();
}

bool UserManager::setPassword(QString name, QString newPass){
    QString hash=md5HashHex(newPass);
    QSqlQuery q(db);
    q.prepare("UPDATE users SET password=:p,last_change=:d WHERE username=:u");
    q.bindValue(":p",hash);
    q.bindValue(":d",QDate::currentDate().toString(Qt::ISODate));
    q.bindValue(":u",name);
    return q.exec();
}

bool UserManager::blockUser(QString name,bool st){
    QSqlQuery q(db);
    q.prepare("UPDATE users SET blocked=:b WHERE username=:u");
    q.bindValue(":b",st?1:0);
    q.bindValue(":u",name);
    return q.exec();
}

bool UserManager::setMinLength(QString name, int value){
    QSqlQuery q(db);
    q.prepare("UPDATE users SET min_len=:v WHERE username=:u");
    q.bindValue(":v", value);
    q.bindValue(":u", name);
    return q.exec();
}

bool UserManager::setExpiration(QString name, int months){
    QSqlQuery q(db);
    q.prepare("UPDATE users SET exp=:m WHERE username=:u");
    q.bindValue(":m", months);
    q.bindValue(":u", name);
    return q.exec();
}

bool UserManager::setRestrictions(QString name, bool enabled){
    QSqlQuery q(db);
    q.prepare("UPDATE users SET restr=:r WHERE username=:u");
    q.bindValue(":r", enabled ? 1 : 0);
    q.bindValue(":u", name);
    return q.exec();
}

std::optional<UserRecord> UserManager::getUser(QString name){
    QSqlQuery q(db);
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
