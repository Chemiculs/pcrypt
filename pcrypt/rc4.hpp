#pragma once
#include <vector>

class _rc4 {
public:
    static __forceinline std::vector<unsigned char> _run(const std::vector<unsigned char>& key, const std::vector<unsigned char>& plaintext) {
        std::vector<unsigned char> S(256);
        for (int i = 0; i < 256; i++) {
            S[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % key.size()]) % 256;
            std::swap(S[i], S[j]);
        }
        std::vector<unsigned char> ciphertext(plaintext.size());
        int i = 0;
        j = 0;
        for (int k = 0; k < plaintext.size(); k++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            std::swap(S[i], S[j]);
            ciphertext[k] = plaintext[k] ^ S[(S[i] + S[j]) % 256];
        }

        return ciphertext;
    }
    static __forceinline void _run_direct(void* key, void* plaintext, size_t len, size_t _kl) {
        std::vector<unsigned char> S(256);
        for (int i = 0; i < 256; i++) {
            S[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + reinterpret_cast<char*>(key)[i % _kl]) % 256;
            std::swap(S[i], S[j]);
        }
        int i = 0;
        j = 0;
        unsigned char* _rawptr = reinterpret_cast<unsigned char*>(plaintext);
        for (int k = 0; k < len; k++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            std::swap(S[i], S[j]);
            _rawptr[k] = _rawptr[k] ^ S[(S[i] + S[j]) % 256];
        }
    }
};