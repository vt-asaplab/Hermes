#pragma once
#include <config.hpp>
#include <unordered_map>
#include "pbc.h"
#include "pbc_test.h"

typedef uint8_t DSSE_Token[37];

struct PEKS_Token {
    element_t     c1;
    element_t     c2;
    element_t     c3;
    unsigned char c4[37];
};

struct PEKS_AggKey {
    mpz_t     k1;
    element_t k2;
    element_t k3;
#ifdef WRITER_EFFICIENCY
    string eepoch;
#endif 
};

struct HICKAE_PrvKey {
    mpz_t tau;
    mpz_t delta;
    mpz_t gamma;
    mpz_t theta; 
    element_t alpha_to_tau_G1;
};

struct HICKAE_PubKey {
    element_t gamma_G2;
    element_t delta_G2;
    element_t theta_G2;
};

#ifdef WRITER_EFFICIENCY
#define DEPTH_EPOCH_TREE (63)
struct Encrypted_Search_Token {
    unordered_map<string, PEKS_Token> data;
};
#endif 


#ifdef WRITER_EFFICIENCY
const int UPDATE_TOKEN_SIZE = 618;

string encode_epoch(string prev_encoded_e) {
    if(prev_encoded_e.length() == DEPTH_EPOCH_TREE) {
        for(int i = DEPTH_EPOCH_TREE - 1; i >= 0; --i) {
            if((prev_encoded_e.substr(0, i) + "1") == prev_encoded_e.substr(0, i + 1)) {
                return prev_encoded_e.substr(0, i) + "2";
            }
        }
    }
    return prev_encoded_e + "1";
}
#else 
const int UPDATE_TOKEN_SIZE = 1159;
#endif 
