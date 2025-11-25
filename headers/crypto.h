#ifndef CRYPTO_H
#define CRYPTO_H

#include <QByteArray>
#include <QString>
#include <optional>

/*
 * crypto.h
 *
 * Заголовок для крипто-утилит:
 * - md5HashHex      : MD5-хеш строки в hex (QByteArray)
 * - deriveDesKey    : получить 8-байтный DES-ключ из keyPhrase + salt
 * - genRandomBytes  : сгенерировать случайные байты (для salt/iv)
 * - encryptCFBWithHeader / decryptCFBWithHeader :
 *       удобные функции для работы с форматом файла:
 *         [MAGIC(8)][SALT(8)][IV(8)][CIPHERTEXT...]
 *
 * Примечание: реализация шифрования использует OpenSSL (EVP API).
 * В .pro нужно линковать -lcrypto (или добавить соответствующие LIBS/INCLUDEPATH для Windows).
 */

static const int CRYPTO_MAGIC_LEN = 8;
static const int CRYPTO_SALT_LEN = 8;
static const int CRYPTO_IV_LEN   = 8;
static const char CRYPTO_MAGIC[CRYPTO_MAGIC_LEN+1] = "QTAUTH23"; // pad to 8 bytes if needed

// Возвращает MD5-хеш (hex) от переданной строки, как QByteArray (ASCII hex)
QByteArray md5HashHex(const QString &password);

// Возвращает 8-байтный ключ DES, полученный из md5(keyPhrase + salt). left(8)
QByteArray deriveDesKey(const QString &keyPhrase, const QByteArray &salt);

// Генерирует случайную последовательность байт длины len
QByteArray genRandomBytes(int len);

// Низкоуровневые: шифровка/расшифровка данных как QByteArray (использует EVP_des_cfb64())
//  - key: 8 байт
//  - iv: 8 байт
// Возвращают пустой QByteArray при ошибке
QByteArray desEncryptCFB_raw(const QByteArray &plaintext, const QByteArray &key, const QByteArray &iv);
QByteArray desDecryptCFB_raw(const QByteArray &ciphertext, const QByteArray &key, const QByteArray &iv);

// Удобные функции-обёртки для файла с заголовком (MAGIC|SALT|IV|CIPHERTEXT)
// - encryptWithHeader генерирует salt и iv случайно, деривирует ключ и возвращает полный буфер
// - decryptWithHeader читает заголовок, деривирует ключ и возвращает расшифрованные байты,
//   или std::nullopt при ошибке (например, неверный формат или ошибка расшифровки)
QByteArray encryptWithHeader(const QString &keyPhrase, const QByteArray &plaintext);
std::optional<QByteArray> decryptWithHeader(const QString &keyPhrase, const QByteArray &blob);

// Утилита: разбирает header и возвращает tuple (salt, iv, ciphertext). При ошибке возвращает nullopt.
std::optional<std::tuple<QByteArray, QByteArray, QByteArray>> parseHeader(const QByteArray &blob);

#endif // CRYPTO_H
