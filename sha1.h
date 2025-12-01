#ifndef SHA1_H
#define SHA1_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

class SHA1 {
public:
    SHA1();
    void reset();
    void update(const unsigned char* data, size_t len);
    void update(const std::vector<unsigned char>& data);
    void update(const std::string& data);
    std::vector<unsigned char> digest();
    std::string hexdigest();

private:
    uint32_t h0, h1, h2, h3, h4;
    std::vector<unsigned char> buffer;
    uint64_t messageLength;

    void processBlock(const unsigned char block[64]);
    void padMessage();
};

#endif // SHA1_H
