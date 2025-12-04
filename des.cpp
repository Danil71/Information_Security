#include "des.h"
#include <cstring>
#include <array>

// --- Таблицы и функции ---
// Для компактности — все таблицы прямо здесь.
// Таблицы взяты из стандартной реализации DES.

static const int IP[64] = {
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};

static const int FP[64] = {
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};

static const int E[48] = {
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
};

static const int P[32] = {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,19,13,30,6,22,11,4
};

static const int PC1[56] = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
};

static const int PC2_full[48] = {
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};

static const int SHIFTS[16] = {
    1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

// S-блоки
static const int S[8][64] = {
    // S1
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
     0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
     15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    // S2
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
     3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
     13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
    // S3
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
     13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
     1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
    // S4
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
     13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
     3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
    // S5
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
     14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
     11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
    // S6
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
     10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
     4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
    // S7
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
     13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
     6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
    // S8
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
     1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
     2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
};

static inline uint64_t permute64(const uint8_t in[8], const int* table, int table_len) {
    uint64_t out = 0;
    for (int i = 0; i < table_len; ++i) {
        int bitpos = table[i] - 1;
        int byte = bitpos / 8;
        int bit = 7 - (bitpos % 8);
        uint8_t b = (in[byte] >> bit) & 1;
        out = (out << 1) | b;
    }
    return out;
}

static inline void uint64_to_bytes(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; --i) {
        out[i] = v & 0xFF;
        v >>= 8;
    }
}

static inline uint64_t bytes_to_uint64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | in[i];
    }
    return v;
}

static inline uint64_t expand32to48(uint32_t r) {
    uint8_t bytes[4];
    bytes[0] = (r >> 24) & 0xFF;
    bytes[1] = (r >> 16) & 0xFF;
    bytes[2] = (r >> 8) & 0xFF;
    bytes[3] = (r) & 0xFF;
    uint64_t res = 0;
    for (int i = 0; i < 48; ++i) {
        int bitpos = E[i] - 1;
        int byte = bitpos / 8;
        int bit = 7 - (bitpos % 8);
        uint8_t b = (bytes[byte] >> bit) & 1;
        res = (res << 1) | b;
    }
    return res;
}

static inline uint32_t permuteP(uint32_t v32) {
    uint8_t bytes[4];
    bytes[0] = (v32 >> 24) & 0xFF;
    bytes[1] = (v32 >> 16) & 0xFF;
    bytes[2] = (v32 >> 8) & 0xFF;
    bytes[3] = (v32) & 0xFF;
    uint32_t out = 0;
    for (int i = 0; i < 32; ++i) {
        int pos = P[i] - 1;
        int by = pos / 8;
        int bt = 7 - (pos % 8);
        uint8_t b = (bytes[by] >> bt) & 1;
        out = (out << 1) | b;
    }
    return out;
}

static inline uint32_t sbox_subst(uint64_t in48) {
    uint32_t out32 = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t six = (in48 >> (42 - 6*i)) & 0x3F;
        int row = ((six & 0x20) >> 4) | (six & 0x01);
        int col = (six >> 1) & 0x0F;
        int val = S[i][row*16 + col];
        out32 = (out32 << 4) | (val & 0xF);
    }
    return out32;
}

static inline void initial_permutation(const uint8_t in[8], uint8_t out[8]) {
    uint64_t perm = permute64(in, IP, 64);
    uint64_to_bytes(perm, out);
}

static inline void final_permutation(const uint8_t in[8], uint8_t out[8]) {
    uint64_t perm = permute64(in, FP, 64);
    uint64_to_bytes(perm, out);
}

static inline void pc1(const uint8_t key[8], uint32_t &C, uint32_t &D) {

    uint8_t keybits[8];
    memcpy(keybits, key, 8);
    uint64_t res = 0;
    for (int i = 0; i < 56; ++i) {
        int pos = PC1[i]-1;
        int by = pos/8;
        int bt = 7 - (pos%8);
        uint8_t b = (keybits[by] >> bt) & 1;
        res = (res << 1) | b;
    }

    C = (uint32_t)((res >> 28) & 0x0FFFFFFF);
    D = (uint32_t)(res & 0x0FFFFFFF);
}

static inline uint64_t cd_to_subkey(uint32_t C, uint32_t D) {

    uint64_t cd = (((uint64_t)C) << 28) | (uint64_t)D;

    uint64_t sub = 0;
    for (int i = 0; i < 48; ++i) {
        int pos = PC2_full[i] - 1;
        uint8_t bit = (cd >> (56 - 1 - pos)) & 1;
        sub = (sub << 1) | bit;
    }
    return sub;
}

DES::DES() {
    subkeysL.fill(0);
    subkeysR.fill(0);
}

void DES::generateSubkeys(const std::array<uint8_t,8>& key) {
    uint32_t C = 0, D = 0;
    pc1(key.data(), C, D);
    for (int i = 0; i < 16; ++i) {
        int s = SHIFTS[i];
        C = ((C << s) | (C >> (28 - s))) & 0x0FFFFFFF;
        D = ((D << s) | (D >> (28 - s))) & 0x0FFFFFFF;
        uint64_t sub = cd_to_subkey(C, D);
        uint32_t left24 = (uint32_t)((sub >> 24) & 0xFFFFFF);
        uint32_t right24 = (uint32_t)(sub & 0xFFFFFF);
        subkeysL[i] = left24;
        subkeysR[i] = right24;
    }
}

void DES::setKey(const std::array<uint8_t,8>& key) {
    generateSubkeys(key);
}

void DES::encryptBlock(const uint8_t in[8], uint8_t out[8]) const {
    uint8_t ip[8];
    initial_permutation(in, ip);

    uint32_t L = (ip[0]<<24) | (ip[1]<<16) | (ip[2]<<8) | ip[3];
    uint32_t R = (ip[4]<<24) | (ip[5]<<16) | (ip[6]<<8) | ip[7];

    for (int i = 0; i < 16; ++i) {
        uint64_t eR = expand32to48(R);
        uint64_t sub = (((uint64_t)subkeysL[i]) << 24) | (uint64_t)subkeysR[i];
        uint64_t x = eR ^ sub;
        uint32_t s_out = sbox_subst(x);
        uint32_t f = permuteP(s_out);
        uint32_t newR = L ^ f;
        L = R;
        R = newR;
    }

    uint8_t preout[8];
    preout[0] = (R >> 24) & 0xFF;
    preout[1] = (R >> 16) & 0xFF;
    preout[2] = (R >> 8) & 0xFF;
    preout[3] = (R) & 0xFF;
    preout[4] = (L >> 24) & 0xFF;
    preout[5] = (L >> 16) & 0xFF;
    preout[6] = (L >> 8) & 0xFF;
    preout[7] = (L) & 0xFF;
    final_permutation(preout, out);
}

void DES::decryptBlock(const uint8_t in[8], uint8_t out[8]) const {
    uint8_t ip[8];
    initial_permutation(in, ip);
    uint32_t L = (ip[0]<<24) | (ip[1]<<16) | (ip[2]<<8) | ip[3];
    uint32_t R = (ip[4]<<24) | (ip[5]<<16) | (ip[6]<<8) | ip[7];

    for (int i = 15; i >= 0; --i) {
        uint64_t eR = expand32to48(R);
        uint64_t sub = (((uint64_t)subkeysL[i]) << 24) | (uint64_t)subkeysR[i];
        uint64_t x = eR ^ sub;
        uint32_t s_out = sbox_subst(x);
        uint32_t f = permuteP(s_out);
        uint32_t newR = L ^ f;
        L = R;
        R = newR;
    }

    uint8_t preout[8];
    preout[0] = (R >> 24) & 0xFF;
    preout[1] = (R >> 16) & 0xFF;
    preout[2] = (R >> 8) & 0xFF;
    preout[3] = (R) & 0xFF;
    preout[4] = (L >> 24) & 0xFF;
    preout[5] = (L >> 16) & 0xFF;
    preout[6] = (L >> 8) & 0xFF;
    preout[7] = (L) & 0xFF;
    final_permutation(preout, out);
}
