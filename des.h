#ifndef DES_H
#define DES_H

#include <vector>
#include <cstdint>
#include <array>

class DES {
public:
    DES();
    void setKey(const std::array<uint8_t,8>& key);
    // encrypt/decrypt one 8-byte block
    void encryptBlock(const uint8_t in[8], uint8_t out[8]) const;
    void decryptBlock(const uint8_t in[8], uint8_t out[8]) const;

private:
    void generateSubkeys(const std::array<uint8_t,8>& key);
    std::array<uint32_t,16> subkeysL;
    std::array<uint32_t,16> subkeysR;
};

#endif // DES_H
