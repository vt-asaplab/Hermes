#pragma once
#include <time.h>
#include <chrono>
#include <vector>
#include <zmq.hpp>
#include <iostream>
#include <sys/time.h>
#include <openssl/sha.h>
#include <emp-tool/emp-tool.h>
#include <emp-agmpc/emp-agmpc.h>
#include "gmp.h"
#include "utils.h"
#include "config.hpp"

// System parameters
mpz_t           q;                          // prime group order
mpz_t           p;                          // p = q - 1
pairing_t       pairing;                    // pairing argument
gmp_randstate_t random_state;               // random state of GMP random generator
uint8_t         rd_data[256];               // buffer for generating random data
mpz_t           alpha;                      // alpha in Zq
element_t       g1;                         // generator in G1
element_t       g2;                         // generator in G2
element_t       gt;                         // generator in GT

// Users' parameters
HICKAE_PrvKey   sk;                         // private key
HICKAE_PubKey   pk;                         // public key
element_t       *public_parameters;         // public parameters
mpz_t           *sigma_hat;                 // 
mpz_t           *sigma_prime;               // classes' secrets
mpz_t           *sigma_class;               // class  
element_t       *class_binding_key;         // class-binding keys 
element_t       **correlation;              // correlation values

// A cryptographic pseudorandom generator
extern PRG      prg;

void HICKAE_Setup(int n) {
    // Curve: phi(n) = lcm(h-1, r-1) 
    // Curve d159: p = 208617601094290618684641029477488665211553761020
    // Curve d201: p = 1047237174547731636071560699617941665718106642306119854716840
    mpz_init(p);
    mpz_set_str(p, "15028799613985034465755506450771561352583254744125520639296541195020", 10);
    
    // Curve: n = h * r 
    // Curve d159: q = 625852803282871856053923088432465995634661283063 
    // Curve d201: q = 2094476214847295281570670320143248652598286201895740019876423
    // For more information: https://crypto.stanford.edu/pbc/manual/ch08s06.html
    mpz_init(q);
    mpz_set_str(q, "15028799613985034465755506450771561352583254744125520639296541195021", 10);

    gmp_randinit_mt(random_state);
    gmp_randseed_ui(random_state, time(NULL));
    
    char s[16384];
    FILE *fp = stdin;
    fp = fopen("../param/d224.param", "r");
    if (!fp) pbc_die("error opening parameter file");
    size_t count = fread(s, 1, 16384, fp);
    if (!count) pbc_die("input error");
    fclose(fp);
    if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");

    mpz_init(alpha);
    prg.reseed((block*)"generateralphaha", 0);
    prg.random_data(rd_data, 28);
    mpz_import(alpha, 28, 1, 1, 0, 0, rd_data);
    mpz_mod(alpha, alpha, q);
    // mpz_urandomb(alpha, random_state, NUM_BITS);
    // printf("alphaha = ");
    // mpz_out_str(stdout, 10, alpha);
    // printf("\n");
    
    // Reuse generators 
    FILE *g1_file = fopen("../param/g1", "rb");
    memset(rd_data, 0, sizeof(rd_data));
    fread(rd_data, 56, 1, g1_file);
    element_init_G1(g1, pairing);
    element_from_bytes(g1, rd_data);
    fclose(g1_file);
    
    FILE *g2_file = fopen("../param/g2", "rb");
    memset(rd_data, 0, sizeof(rd_data));
    fread(rd_data, 168, 1, g2_file);
    element_init_G2(g2, pairing);
    element_from_bytes(g2, rd_data);
    fclose(g2_file);
    
    /*
    // Get new random generators
    FILE *g1f = fopen("../g1", "wb");
    element_init_G1(g1, pairing);
    element_random(g1);
    int len = element_to_bytes(rd_data, g1);
    fwrite(rd_data, len, 1, g1f);
    fclose(g1f);

    FILE *g2f = fopen("../g2", "wb");
    element_init_G2(g2, pairing);
    element_random(g2);
    len = element_to_bytes(rd_data, g2);
    fwrite(rd_data, len, 1, g2f);
    fclose(g2f);
    */

    element_init_GT(gt, pairing);
    element_pairing(gt, g1, g2); 

    sigma_hat = new mpz_t[n];
    public_parameters = new element_t[n];

    mpz_t tmp;
    mpz_init(tmp);

    for(int i = 0; i < n; ++i) { 
        mpz_init(sigma_hat[i]);
        prg.reseed((block*)"generatersigmahat", i);
        prg.random_data(rd_data, 28);
        mpz_import(sigma_hat[i], 28, 1, 1, 0, 0, rd_data);
        mpz_mod(sigma_hat[i], sigma_hat[i], p);
        mpz_neg(tmp, sigma_hat[i]);
        mpz_mod(tmp, tmp, p);
        mpz_powm(tmp, alpha, tmp, q);
        element_init_G2(public_parameters[i], pairing);
        element_mul_mpz(public_parameters[i], g2, tmp);
    }
}

void HICKAE_KeyGen() {
    mpz_init(sk.tau);
    prg.reseed((block*)"generatertau", 0);
    prg.random_data(rd_data, 28);
    mpz_import(sk.tau, 28, 1, 1, 0, 0, rd_data);
    mpz_mod(sk.tau, sk.tau, p);
    
    // mpz_urandomb(tau, random_state, NUM_BITS);
    // printf("tau = ");
    // mpz_out_str(stdout, 10, tau);
    // printf("\n");
    mpz_t alpha_to_tau;
    mpz_init(alpha_to_tau);
    mpz_powm(alpha_to_tau, alpha, sk.tau, q);
    element_init_G1(sk.alpha_to_tau_G1, pairing);    
    element_mul_mpz(sk.alpha_to_tau_G1, g1, alpha_to_tau);
    
    mpz_init(sk.gamma);
    prg.reseed((block*)"generatergamma", 0);
    prg.random_data(rd_data, 28);
    // mpz_urandomb(gamma, random_state, NUM_BITS);
    mpz_import(sk.gamma, 28, 1, 1, 0, 0, rd_data);
    mpz_mod(sk.gamma, sk.gamma, q);
    // printf("gamma = ");
    // mpz_out_str(stdout, 10, gamma);
    // printf("\n"); 

    mpz_init(sk.delta);
    prg.reseed((block*)"generaterdelta", 0);
    prg.random_data(rd_data, 28);
    // mpz_urandomb(delta, random_state, NUM_BITS);
    mpz_import(sk.delta, 28, 1, 1, 0, 0, rd_data);
    mpz_mod(sk.delta, sk.delta, q);
    // printf("delta = ");
    // mpz_out_str(stdout, 10, delta);
    // printf("\n");
    
    mpz_init(sk.theta);
    prg.reseed((block*)"generatertheta", 0);
    prg.random_data(rd_data, 28);
    // mpz_urandomb(theta, random_state, NUM_BITS);
    mpz_import(sk.theta, 28, 1, 1, 0, 0, rd_data);
    mpz_mod(sk.theta, sk.theta, q);
    // printf("theta = ");
    // mpz_out_str(stdout, 10, theta);
    // printf("\n");

    element_init_G2(pk.gamma_G2, pairing);
    element_mul_mpz(pk.gamma_G2, g2, sk.gamma);

    element_init_G2(pk.theta_G2, pairing);
    element_mul_mpz(pk.theta_G2, g2, sk.theta);

    element_init_G2(pk.delta_G2, pairing);
    element_mul_mpz(pk.delta_G2, g2, sk.delta);
}

void HICKAE_IGen(int num_writers) {
    mpz_t tmp;
    mpz_init(tmp);
    
    sigma_prime = new mpz_t[num_writers];
    class_binding_key = new element_t[num_writers];

    for(int i = 0; i < num_writers; ++i) { 
        mpz_init(sigma_prime[i]);
        prg.reseed((block*)"generatersigmaprime", i);
        prg.random_data(rd_data, 28);
        mpz_import(sigma_prime[i], 28, 1, 1, 0, 0, rd_data);
        mpz_mod(sigma_prime[i], sigma_prime[i], p);
        mpz_neg(tmp, sigma_prime[i]);
        mpz_mod(tmp, tmp, p);
        mpz_powm(tmp, alpha, tmp, q);
        // mpz_invert(tmp, tmp, q);
        element_init_G2(class_binding_key[i], pairing);
        element_mul_mpz(class_binding_key[i], public_parameters[i], tmp);
    }
}

void HICKAE_Prep(int num_writers) {
    element_t temp;
    element_init_G1(temp, pairing);

    sigma_class = new mpz_t[num_writers];

    for(int i = 0; i < num_writers; ++i) {
        mpz_init(sigma_class[i]);
        mpz_add(sigma_class[i], sigma_hat[i], sigma_prime[i]);
        mpz_mod(sigma_class[i], sigma_class[i], p);
    }

    mpz_t tmp;
    mpz_init(tmp);

    correlation = new element_t*[num_writers];
    for(int i = 0; i < num_writers; ++i) {
        correlation[i] = new element_t[num_writers];
        for(int j = 0; j < num_writers; ++j) 
            if(i != j) {
                mpz_add(tmp, sk.tau, sigma_class[i]);
                mpz_mod(tmp, tmp, p);
                mpz_sub(tmp, tmp, sigma_class[j]);
                mpz_mod(tmp, tmp, p);
                mpz_powm(tmp, alpha, tmp, q);
                element_init_G1(correlation[i][j], pairing);
                element_mul_mpz(correlation[i][j], g1, tmp);
            }
    }
}

void HICKAE_Encrypt(int wid, char *id, unsigned char *m, PEKS_Token *c) {
    // auto start = clock_start();
    mpz_t r;
    mpz_init(r);
    mpz_urandomb(r, random_state, 224);
    // printf("r = ");
    // mpz_out_str(stdout, 10, r);
    // printf("\n");
    element_init_G2(c->c1, pairing);
    element_mul_mpz(c->c1, g2, r);
    
    element_init_G2(c->c2, pairing);
    element_mul_mpz(c->c2, pk.theta_G2, r);
    
    element_init_G2(c->c3, pairing);
    element_add(c->c3, pk.gamma_G2, class_binding_key[wid]);
    element_mul_mpz(c->c3, c->c3, r);
    
    SHA512_CTX sha512;
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, id, strlen(id));
    SHA512_Final(hash, &sha512);

    element_t h_G1;
    element_init_G1(h_G1, pairing);
    element_from_hash(h_G1, hash, SHA512_DIGEST_LENGTH);

    element_t ut;
    element_init_GT(ut, pairing);
    element_pairing(ut, h_G1, pk.delta_G2);
    element_mul_mpz(ut, ut, r);

    unsigned char temp[256];
    memset(temp, 0, sizeof(temp));
    int len = element_to_bytes(temp, ut);

    // cout << "len = " << len << endl;
    
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, temp, len);
    SHA512_Final(hash, &sha512);

    // c->c4 = new unsigned char[37];
    char indicator[] = "VALID";
    for(int i = 0; i < 5; ++i)
        c->c4[i] = indicator[i] ^ hash[i];
    for(int i = 0, j = 5; i < 32; ++i, ++j)
        c->c4[j] = m[i] ^ hash[j];
    
    // cout << "Encryption time: " << time_from(start) << endl;
}

void HICKAE_Extract(vector<int> &writer_subset, char *id, PEKS_AggKey *agg_key) {
    mpz_t tau_prime;
    mpz_init(tau_prime);
    mpz_urandomb(tau_prime, random_state, NUM_BITS);
    mpz_mod(tau_prime, tau_prime, p);
    
    mpz_t alpha_pow_tau_prime;
    mpz_init(alpha_pow_tau_prime);
    mpz_powm(alpha_pow_tau_prime, alpha, tau_prime, q);

    mpz_init(agg_key->k1);
    mpz_add(agg_key->k1, alpha_pow_tau_prime, sk.theta);
    mpz_mod(agg_key->k1, agg_key->k1, q);

    SHA512_CTX sha512;
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, id, strlen(id));
    SHA512_Final(hash, &sha512);

    element_t h_G1;
    element_init_G1(h_G1, pairing);
    element_from_hash(h_G1, hash, SHA512_DIGEST_LENGTH);

    element_init_G1(agg_key->k2, pairing);
    element_mul_mpz(agg_key->k2, h_G1, sk.delta);

    mpz_neg(tau_prime, tau_prime);
    mpz_mod(tau_prime, tau_prime, p);
    mpz_powm(tau_prime, alpha, tau_prime, q);
    element_mul_mpz(agg_key->k2, agg_key->k2, tau_prime);

    element_init_G1(agg_key->k3, pairing);
    element_set0(agg_key->k3);
    
    mpz_t key_id;
    mpz_init(key_id);

    element_t temp;
    element_init_G1(temp, pairing);

    for(int i = 0; i < writer_subset.size(); ++i) {
        mpz_powm(key_id, alpha, sigma_class[writer_subset[i]], q);
        element_mul_mpz(temp, sk.alpha_to_tau_G1, key_id);
        element_add(agg_key->k3, agg_key->k3, temp);
    }
    
    element_mul_mpz(temp, agg_key->k3, sk.gamma);
    element_add(agg_key->k2, agg_key->k2, temp);
    element_add(agg_key->k2, agg_key->k2, sk.alpha_to_tau_G1);

    element_mul_mpz(agg_key->k3, agg_key->k3, alpha_pow_tau_prime);
}

void HICKAE_Extract(vector<int> &writer_subset, string *id, PEKS_AggKey *agg_key, int n) {
    mpz_t *tau_prime = new mpz_t[n];
    for(int k = 0; k < n; ++k) {
        mpz_init(tau_prime[k]);
        mpz_urandomb(tau_prime[k], random_state, NUM_BITS);
        mpz_mod(tau_prime[k], tau_prime[k], p);
    }
    
    mpz_t *alpha_pow_tau_prime = new mpz_t[n];
    for(int k = 0; k < n; ++k) {
        mpz_init(alpha_pow_tau_prime[k]);
        mpz_powm(alpha_pow_tau_prime[k], alpha, tau_prime[k], q);
        mpz_init(agg_key[k].k1);
        mpz_add(agg_key[k].k1, alpha_pow_tau_prime[k], sk.theta);
        mpz_mod(agg_key[k].k1, agg_key[k].k1, q);
    }
    
    SHA512_CTX sha512;
    unsigned char hash[SHA512_DIGEST_LENGTH];

    for(int k = 0; k < n; ++k) {
        SHA512_Init(&sha512);
        SHA512_Update(&sha512, id[k].c_str(), id[k].length());
        SHA512_Final(hash, &sha512);

        element_t h_G1;
        element_init_G1(h_G1, pairing);
        element_from_hash(h_G1, hash, SHA512_DIGEST_LENGTH);

        element_init_G1(agg_key[k].k2, pairing);
        element_mul_mpz(agg_key[k].k2, h_G1, sk.delta);

        mpz_neg(tau_prime[k], tau_prime[k]);
        mpz_mod(tau_prime[k], tau_prime[k], p);
        mpz_powm(tau_prime[k], alpha, tau_prime[k], q);
        element_mul_mpz(agg_key[k].k2, agg_key[k].k2, tau_prime[k]);

        element_init_G1(agg_key[k].k3, pairing);
        element_set0(agg_key[k].k3);
    }
    
    mpz_t key_id;
    mpz_init(key_id);

    element_t temp;
    element_init_G1(temp, pairing);

    for(int i = 0; i < writer_subset.size(); ++i) {
        mpz_powm(key_id, alpha, sigma_class[writer_subset[i]], q);
        element_mul_mpz(temp, sk.alpha_to_tau_G1, key_id);
        element_add(agg_key[0].k3, agg_key[0].k3, temp);
    }
    element_mul_mpz(temp, agg_key[0].k3, sk.gamma);

    for(int k = 1; k < n; ++k) 
        element_set(agg_key[k].k3, agg_key[0].k3);

    element_add(temp, temp, sk.alpha_to_tau_G1);

    for(int k = 0; k < n; ++k) {
        element_add(agg_key[k].k2, agg_key[k].k2, temp);
        element_mul_mpz(agg_key[k].k3, agg_key[k].k3, alpha_pow_tau_prime[k]);
    }
    
    delete [] tau_prime;
    delete [] alpha_pow_tau_prime;
}

bool HICKAE_Decrypt(vector<int> &writer_subset, int &wid, PEKS_AggKey &agg_key, PEKS_Token &c, unsigned char *m) {
    // auto start = clock_start();

    element_t temp;
    element_init_G1(temp, pairing);
    element_set(temp, agg_key.k2);
    
    for(int i = 0; i < writer_subset.size(); ++i) {
        if(writer_subset[i] == wid) continue;
        element_add(temp, temp, correlation[writer_subset[i]][wid]);
    }

    element_t temp_g2;
    element_init_G2(temp_g2, pairing);
    element_mul_mpz(temp_g2, c.c1, agg_key.k1);
    element_sub(temp_g2, temp_g2, c.c2); 
    
    element_t ut;
    element_init_GT(ut, pairing);
    element_pairing(ut, temp, temp_g2);

    element_t temp_gt;
    element_init_GT(temp_gt, pairing);
    element_pairing(temp_gt, agg_key.k3, c.c3);
    
    element_sub(ut, ut, temp_gt);
    
    SHA512_CTX sha512;
    unsigned char hash[SHA512_DIGEST_LENGTH];
    unsigned char ut_bytes[256];
    memset(ut_bytes, 0, sizeof(ut_bytes));
    int len = element_to_bytes(ut_bytes, ut);

    SHA512_Init(&sha512);
    SHA512_Update(&sha512, ut_bytes, len);
    SHA512_Final(hash, &sha512);
    
    memset(m, 0, 37); 

    for(int i = 0; i < 5; ++i) {
        m[i] = c.c4[i] ^ hash[i];
    }
    
    if(strcmp((const char*)m, "VALID") != 0)
        return false;   
    
    for(int i = 5; i < 37; ++i)
        m[i] = c.c4[i] ^ hash[i];
    
    // cout << "Decryption time: " << time_from(start) << endl;
    return true;
}


