#include "headers/crypto.h"
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDebug>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* -----------------------------
   MD5 hashing
   ----------------------------- */
QByteArray md5HashHex(const QString &password) {
    QByteArray bin = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Md5);
    return bin.toHex(); // hex ascii
}

/* -----------------------------
   Key derivation (simple MD5-based)
   md5(keyPhrase + salt) -> 16 bytes -> take first 8 bytes as DES key
   ----------------------------- */
QByteArray deriveDesKey(const QString &keyPhrase, const QByteArray &salt) {
    QByteArray combined = keyPhrase.toUtf8() + salt;
    QByteArray md = QCryptographicHash::hash(combined, QCryptographicHash::Md5); // 16 bytes
    return md.left(8);
}

/* -----------------------------
   Random bytes generation
   ----------------------------- */
QByteArray genRandomBytes(int len) {
    QByteArray out;
    out.resize(len);
    // Prefer OpenSSL RAND_bytes if available for crypto strength
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), len) == 1) {
        return out;
    } else {
        // fallback to QRandomGenerator (less ideal but acceptable for lab)
        auto rng = QRandomGenerator::global();
        for (int i = 0; i < len; ++i) out[i] = static_cast<char>(rng->bounded(0,256));
        return out;
    }
}

/* -----------------------------
   Low-level OpenSSL EVP wrapper for DES-CFB
   ----------------------------- */

static void logOpenSSLErrors() {
    unsigned long e = ERR_get_error();
    while (e) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        qWarning() << "OpenSSL error:" << buf;
        e = ERR_get_error();
    }
}

QByteArray desEncryptCFB_raw(const QByteArray &plaintext, const QByteArray &key, const QByteArray &iv) {
    if (key.size() != 8 || iv.size() != 8) {
        qWarning() << "DES key or IV must be 8 bytes";
        return {};
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        logOpenSSLErrors();
        return {};
    }

    const EVP_CIPHER *cipher = EVP_des_cfb64(); // DES CFB-64
    if (!cipher) {
        qWarning() << "EVP_des_cfb64() not available";
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int ok = EVP_CipherInit_ex(ctx, cipher, nullptr,
                               reinterpret_cast<const unsigned char*>(key.constData()),
                               reinterpret_cast<const unsigned char*>(iv.constData()), 1);
    if (ok != 1) {
        qWarning() << "EVP_CipherInit_ex failed";
        logOpenSSLErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    QByteArray out;
    out.resize(plaintext.size() + EVP_CIPHER_block_size(cipher));
    int outlen1 = 0;
    if (EVP_CipherUpdate(ctx,
                         reinterpret_cast<unsigned char*>(out.data()), &outlen1,
                         reinterpret_cast<const unsigned char*>(plaintext.constData()), plaintext.size()) != 1) {
        qWarning() << "EVP_CipherUpdate failed";
        logOpenSSLErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int outlen2 = 0;
    if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char*>(out.data()) + outlen1, &outlen2) != 1) {
        // For CFB, Final may or may not add bytes; treat conservatively
        // We'll not treat this as fatal, but log if error
        // qWarning() << "EVP_CipherFinal_ex returned non-1";
        logOpenSSLErrors();
    }

    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

QByteArray desDecryptCFB_raw(const QByteArray &ciphertext, const QByteArray &key, const QByteArray &iv) {
    if (key.size() != 8 || iv.size() != 8) {
        qWarning() << "DES key or IV must be 8 bytes";
        return {};
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        logOpenSSLErrors();
        return {};
    }

    const EVP_CIPHER *cipher = EVP_des_cfb64();
    if (!cipher) {
        qWarning() << "EVP_des_cfb64() not available";
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int ok = EVP_CipherInit_ex(ctx, cipher, nullptr,
                               reinterpret_cast<const unsigned char*>(key.constData()),
                               reinterpret_cast<const unsigned char*>(iv.constData()), 0);
    if (ok != 1) {
        qWarning() << "EVP_CipherInit_ex (decrypt) failed";
        logOpenSSLErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    QByteArray out;
    out.resize(ciphertext.size() + EVP_CIPHER_block_size(cipher));
    int outlen1 = 0;
    if (EVP_CipherUpdate(ctx,
                         reinterpret_cast<unsigned char*>(out.data()), &outlen1,
                         reinterpret_cast<const unsigned char*>(ciphertext.constData()), ciphertext.size()) != 1) {
        qWarning() << "EVP_CipherUpdate (decrypt) failed";
        logOpenSSLErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int outlen2 = 0;
    if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char*>(out.data()) + outlen1, &outlen2) != 1) {
        // For CFB, Final may be trivial; still log
        logOpenSSLErrors();
    }

    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

/* -----------------------------
   Header helpers: format:
   [MAGIC(8)] [SALT(8)] [IV(8)] [CIPHERTEXT...]
   ----------------------------- */

std::optional<std::tuple<QByteArray, QByteArray, QByteArray>> parseHeader(const QByteArray &blob) {
    if (blob.size() < (CRYPTO_MAGIC_LEN + CRYPTO_SALT_LEN + CRYPTO_IV_LEN)) return std::nullopt;
    QByteArray magic = blob.left(CRYPTO_MAGIC_LEN);
    // trim trailing zeros and compare prefix
    QByteArray magicTrim = magic;
    // Accept if magic starts with defined prefix
    QByteArray expected = QByteArray::fromRawData(CRYPTO_MAGIC, CRYPTO_MAGIC_LEN);
    if (!magic.startsWith(expected.left(expected.indexOf('\0') >= 0 ? expected.indexOf('\0') : expected.size()))) {
        // also accept if first bytes equal ASCII "QTAUTH23" ignoring trailing zeros
        // if not matched, continue but don't fail early — prefer strict check
        // but for lab we check prefix:
        if (!magic.startsWith(expected)) return std::nullopt;
    }

    int pos = 0;
    pos += CRYPTO_MAGIC_LEN;
    QByteArray salt = blob.mid(pos, CRYPTO_SALT_LEN); pos += CRYPTO_SALT_LEN;
    QByteArray iv   = blob.mid(pos, CRYPTO_IV_LEN); pos += CRYPTO_IV_LEN;
    QByteArray cipher = blob.mid(pos);
    return std::make_tuple(salt, iv, cipher);
}

QByteArray encryptWithHeader(const QString &keyPhrase, const QByteArray &plaintext) {
    QByteArray salt = genRandomBytes(CRYPTO_SALT_LEN);
    QByteArray iv   = genRandomBytes(CRYPTO_IV_LEN);
    QByteArray key  = deriveDesKey(keyPhrase, salt); // 8 bytes

    QByteArray cipher = desEncryptCFB_raw(plaintext, key, iv);
    if (cipher.isEmpty()) {
        qWarning() << "Encryption failed";
        return {};
    }

    QByteArray out;
    // MAGIC (8) - pad with zeros if needed
    QByteArray magic(CRYPTO_MAGIC, CRYPTO_MAGIC_LEN);
    out.append(magic);
    out.append(salt);
    out.append(iv);
    out.append(cipher);
    return out;
}

std::optional<QByteArray> decryptWithHeader(const QString &keyPhrase, const QByteArray &blob) {
    auto parsed = parseHeader(blob);
    if (!parsed) return std::nullopt;
    QByteArray salt, iv, cipher;
    std::tie(salt, iv, cipher) = *parsed;
    QByteArray key = deriveDesKey(keyPhrase, salt);
    QByteArray plain = desDecryptCFB_raw(cipher, key, iv);
    if (plain.isEmpty()) {
        // Could be wrong key or decryption error
        return std::nullopt;
    }
    return plain;
}

/* -----------------------------
   Small usage example (for documentation):
   QByteArray plain = QFile::readAllBytes("users_temp.db");
   QByteArray enc = encryptWithHeader(keyPhrase, plain);
   // write enc to users.enc
   // later:
   auto maybe_plain = decryptWithHeader(keyPhrase, encBlob);
   if (maybe_plain) { // success }
   ----------------------------- */

