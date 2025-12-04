#include "sha1.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>

static inline uint32_t rol(uint32_t value, unsigned int bits) {
    return (value << bits) | (value >> (32 - bits));
}

SHA1::SHA1() {
    reset();
}

void SHA1::reset() {
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;
    buffer.clear();
    messageLength = 0;
}

void SHA1::update(const unsigned char* data, size_t len) {
    if (!data || len == 0) return;

    messageLength += len * 8;

    for (size_t i = 0; i < len; i++) {
        buffer.push_back(data[i]);

        if (buffer.size() == 64) {
            processBlock(buffer.data());
            buffer.clear();
        }
    }
}

void SHA1::update(const std::vector<unsigned char>& data) {
    if (!data.empty()) update(data.data(), data.size());
}

void SHA1::update(const std::string& data) {
    if (!data.empty()) update(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

void SHA1::processBlock(const unsigned char block[64]) {
    uint32_t w[80];

    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i*4]) << 24) |
               (static_cast<uint32_t>(block[i*4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i*4 + 2]) << 8) |
               static_cast<uint32_t>(block[i*4 + 3]);
    }

    for (int i = 16; i < 80; ++i) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;

    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
}

void SHA1::padMessage() {
    buffer.push_back(0x80);

    while (buffer.size() % 64 != 56) {
        buffer.push_back(0x00);
    }

    uint64_t bitLength = messageLength;

    for (int i = 7; i >= 0; --i) {
        buffer.push_back(static_cast<unsigned char>((bitLength >> (i * 8)) & 0xFF));
    }
}

std::vector<unsigned char> SHA1::digest() {
    SHA1 copy = *this;

    copy.padMessage();

    for (size_t i = 0; i < copy.buffer.size(); i += 64) {
        if (i + 64 <= copy.buffer.size()) {
            copy.processBlock(copy.buffer.data() + i);
        }
    }

    std::vector<unsigned char> result(20);

    result[0]  = static_cast<unsigned char>((copy.h0 >> 24) & 0xFF);
    result[1]  = static_cast<unsigned char>((copy.h0 >> 16) & 0xFF);
    result[2]  = static_cast<unsigned char>((copy.h0 >> 8) & 0xFF);
    result[3]  = static_cast<unsigned char>(copy.h0 & 0xFF);

    result[4]  = static_cast<unsigned char>((copy.h1 >> 24) & 0xFF);
    result[5]  = static_cast<unsigned char>((copy.h1 >> 16) & 0xFF);
    result[6]  = static_cast<unsigned char>((copy.h1 >> 8) & 0xFF);
    result[7]  = static_cast<unsigned char>(copy.h1 & 0xFF);

    result[8]  = static_cast<unsigned char>((copy.h2 >> 24) & 0xFF);
    result[9]  = static_cast<unsigned char>((copy.h2 >> 16) & 0xFF);
    result[10] = static_cast<unsigned char>((copy.h2 >> 8) & 0xFF);
    result[11] = static_cast<unsigned char>(copy.h2 & 0xFF);

    result[12] = static_cast<unsigned char>((copy.h3 >> 24) & 0xFF);
    result[13] = static_cast<unsigned char>((copy.h3 >> 16) & 0xFF);
    result[14] = static_cast<unsigned char>((copy.h3 >> 8) & 0xFF);
    result[15] = static_cast<unsigned char>(copy.h3 & 0xFF);

    result[16] = static_cast<unsigned char>((copy.h4 >> 24) & 0xFF);
    result[17] = static_cast<unsigned char>((copy.h4 >> 16) & 0xFF);
    result[18] = static_cast<unsigned char>((copy.h4 >> 8) & 0xFF);
    result[19] = static_cast<unsigned char>(copy.h4 & 0xFF);

    return result;
}

std::string SHA1::hexdigest() {
    auto d = digest();
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (unsigned char c : d) {
        oss << std::setw(2) << static_cast<unsigned int>(c);
    }

    return oss.str();
}
