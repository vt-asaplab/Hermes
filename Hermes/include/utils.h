#pragma once
#include <iostream>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <types.hpp>
#include "MurmurHash3.h"

using namespace std;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int prf(unsigned char *seed, int seed_len, unsigned char *key, unsigned char *output) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, output, &len, seed, seed_len))
        handleErrors();

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, output + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

array<uint64_t, 2> mm_hash(const uint8_t* data, size_t len) {
    array<uint64_t, 2> hash_value;
    MurmurHash3_x64_128(data, len, 0, hash_value.data());
    return hash_value;
}

inline uint64_t nth_hash(uint8_t i, uint64_t hash_a, uint64_t hash_b, uint64_t filter_size) {
    return (hash_a + i * hash_b) % filter_size;
}

int count_lines(string file_path) {
    int number_of_lines = 0;
    std::string line;
    std::ifstream myfile(file_path);
    
    while (std::getline(myfile, line))
        ++number_of_lines;
    
    return number_of_lines;
}