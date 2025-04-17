#include <iostream>
#include <fstream>
#include <sstream>
#include <zmq.hpp>
#include <emp-tool/emp-tool.h>
#include <emp-agmpc/emp-agmpc.h>
#include <utils.h>
#include "hickae.hpp"
#include "ThreadPool.h"

using namespace std;

PRG            prg; 
SHA512_CTX     sha512;
unsigned char  tmp[64];
char           addr[21];
bool           found;
unsigned char  search_token[32];
int            num_writers;
zmq::context_t *context_server;
zmq::socket_t  *socket_server;
mutex          mtx;
int            **output;
string         encoded_epoch;
uint64_t       epoch;

// DSSE Search Indices
unordered_map<string, DSSE_Token>         *EDTkn;

// PKSE Search Indices
unordered_map<string, vector<PEKS_Token>> *PTkn;
#ifdef WRITER_EFFICIENCY
unordered_map<string, vector<Encrypted_Search_Token>> *WTkn;
#else 
unordered_map<string, vector<PEKS_Token>> *WTkn;
#endif 

// For debugging
unordered_map<string, uint64_t>           *state;

void init(int num_writers) {
    EDTkn = new unordered_map<string, DSSE_Token>[num_writers];
    state = new unordered_map<string, uint64_t>[num_writers];

    PTkn = new unordered_map<string, vector<PEKS_Token>>[num_writers];
#ifdef WRITER_EFFICIENCY
    WTkn = new unordered_map<string, vector<Encrypted_Search_Token>>[num_writers];
#else 
    WTkn = new unordered_map<string, vector<PEKS_Token>>[num_writers];
#endif 

#ifdef WRITER_EFFICIENCY
    vector<string> gamma_t;
    string padded_encoded_epoch = encoded_epoch;
    padded_encoded_epoch.insert(padded_encoded_epoch.end(), DEPTH_EPOCH_TREE - padded_encoded_epoch.size(), '0');
    gamma_t.push_back(padded_encoded_epoch);

    for(int i = DEPTH_EPOCH_TREE - 1; i >= 0; --i) {
        if((encoded_epoch.substr(0, i) + "1") == encoded_epoch.substr(0, i + 1)) {
            string temp = encoded_epoch.substr(0, i) + "2";
            temp.insert(temp.end(), DEPTH_EPOCH_TREE - temp.size(), '0');
            gamma_t.push_back(temp);
        }
    }
#endif 

    /*
    cout << "Gamma: " << endl;
    for(int i = 0; i < gamma_t.size(); ++i) {
        cout << gamma_t[i] << endl;
    } 
    */
    
    vector<future<void>> threads;
    ThreadPool pool(MAX_THREADS_INIT);
    
    vector<int> writer_set;

    for(int writer_id = num_writers - 1; writer_id >= 0; --writer_id) 
        writer_set.push_back(writer_id);
    
    for(int t = 0; t < MAX_THREADS_INIT; ++t) {
#ifdef WRITER_EFFICIENCY
        threads.push_back(pool.enqueue([t, &writer_set, &gamma_t]() {
#else 
        threads.push_back(pool.enqueue([t, &writer_set]() {
#endif 
            int writer_id;
            string line;
            string keyword;
            int file_id;
            SHA512_CTX sha512;
            char addr[21];
            unsigned char tmp[SHA512_DIGEST_LENGTH];
            
            while(!writer_set.empty()) {
                mtx.lock();
                if(!writer_set.empty()) {
                    writer_id = writer_set.back();
                    writer_set.pop_back();
                }
                else {
                    mtx.unlock();
                    break;
                }
                cout << "Writer ID: " << (writer_id + 1) << endl;
                mtx.unlock();

                // For quick index initialization on the server side
                unsigned char writer_secret_key[32];
                prg.reseed((block*)"generaterwritersecretkeys", writer_id+1);
                prg.random_block((block*)writer_secret_key, 2);
                string user_database = to_string(writer_id+1) + ".txt";
                // int num_keywords = count_lines("../database/" + user_database); 
                // cout << "#Keywords: " << num_keywords << endl;

                ifstream file("../database/" + user_database);

                while(getline(file, line)) {
                    stringstream wss(line);
                    wss >> keyword;
                    // cout << "Keyword: " << keyword << endl;
                    istringstream iss(line.substr(keyword.length() + 1));
                    state[writer_id][keyword] = 0;
                    
                    int file_id;
                    unsigned char token[32];
                    unsigned char prev_token[32];
                    memset(prev_token, 0, 32);
                    
                    while(iss >> file_id) {
                        string seed = keyword + to_string(state[writer_id][keyword]);
                        prf((unsigned char *)seed.c_str(), seed.length(), writer_secret_key, token);
                        
                        // cout << "PRF: ";
                        // for(int i = 0; i < 32; ++i)    
                        //     cout << (int)token[i] << " ";
                        // cout << endl;

                        SHA512_Init(&sha512);
                        SHA512_Update(&sha512, token, 16);
                        SHA512_Final(tmp, &sha512);
                        
                        memset(addr, 0, sizeof(addr));
                        for (int j = 0; j < 10; ++j) 
                            sprintf(addr+j*2, "%02x", tmp[j]);

                        DSSE_Token value;   
                        memset(value, 0, sizeof(DSSE_Token));
                        value[0] = 1;                                       // 1 = add, 0 = delete
                        memcpy((uint8_t*)value + 1, &file_id, sizeof(int)); // file id
                        memcpy((uint8_t*)value + 5, prev_token, 32);        // previous token

                        for(int j = 0; j < 37; ++j) 
                            value[j] ^= tmp[j+10];

                        // Put it to search index EDB
                        memcpy(EDTkn[writer_id][addr], value, sizeof(DSSE_Token));

                        // Update previous token
                        memcpy(prev_token, token, 32);
                        state[writer_id][keyword]++;
                    }

                    array<uint64_t, 2> hash_value = mm_hash((uint8_t*)keyword.c_str(), keyword.length());
#ifdef SEARCH_EFFICIENCY
                    int num_partitions = NUM_PARTITIONS;
                    uint64_t pid = ((hash_value[0] % num_partitions) << 2) | RECURSIVE_LEVEL;
#else 
                    uint64_t pid = hash_value[0] % MAX_PARTITIONS;
#endif              
                    // Compute partition tag from writer's secret key 
                    unsigned char partition_tag[32];
                    prf((unsigned char *)&pid, sizeof(pid), writer_secret_key, partition_tag);

                    // Convert partition tag to a string in hex
                    memset(addr, 0, sizeof(addr));
                    for (int j = 0; j < 10; ++j) 
                        sprintf(addr+j*2, "%02x", partition_tag[j]);   
                             
                    string paddr;
                    paddr.assign(addr, addr + 20);

                    string last_paddr = paddr;
#ifdef SEARCH_EFFICIENCY          
                    bool exist = false; // Check if partition has exists or not
                    
                    if(WTkn[writer_id][paddr].empty()) {
                        // Recursive until before root level
                        for(int k = 1; k < RECURSIVE_LEVEL; ++k) {
                            PEKS_Token eptkn;
                            HICKAE_Encrypt(writer_id, (char*)to_string(pid).c_str(), partition_tag, &eptkn);
                            
                            num_partitions /= PARTITION_SIZE;
                            hash_value = mm_hash((uint8_t*)&pid, sizeof(pid));
                            pid = ((hash_value[0] % num_partitions) << 2) | (RECURSIVE_LEVEL - k);
                            
                            prf((unsigned char *)&pid, sizeof(pid), writer_secret_key, partition_tag);
                            
                            memset(addr, 0, sizeof(addr));
                            for (int j = 0; j < 10; ++j) 
                                sprintf(addr+j*2, "%02x", partition_tag[j]);            
                            paddr.assign(addr, addr + 20);
                            
                            if(PTkn[writer_id][paddr].empty()) exist = false;
                            else exist = true;
                            PTkn[writer_id][paddr].push_back(eptkn);
                            if(exist) break;
                        }
                        
                        // Root level 0
                        if(!exist) {
                            PEKS_Token eptkn;
                            HICKAE_Encrypt(writer_id, (char*)to_string(pid).c_str(), partition_tag, &eptkn);
                            PTkn[writer_id][""].push_back(eptkn);
                        }
                    }
#else 
                    if(WTkn[writer_id][paddr].empty()) {
                        PEKS_Token eptkn;
                        HICKAE_Encrypt(writer_id, (char*)to_string(pid).c_str(), partition_tag, &eptkn);
                        PTkn[writer_id][""].push_back(eptkn);
                    }
#endif              
                    paddr = last_paddr;
                    string id;
#ifdef WRITER_EFFICIENCY
                    Encrypted_Search_Token ewtkn;
                    for(int i = 0; i < gamma_t.size(); ++i) {
                        id = keyword + gamma_t[i];
                        HICKAE_Encrypt(writer_id, (char*)id.c_str(), token, &ewtkn.data[gamma_t[i]]);
                    }
                    WTkn[writer_id][paddr].push_back(ewtkn);
#else               
                    id = keyword + to_string(epoch);
                    PEKS_Token ewtkn; 
                    HICKAE_Encrypt(writer_id, (char*)id.c_str(), prev_token, &ewtkn);
                    WTkn[writer_id][paddr].push_back(ewtkn);
#endif 
                }
                file.close();
            }
            mtx.lock();
            cout << "Thread " << t << " ends." << endl;
            mtx.unlock();
        }));
    }
    joinNclean(threads);
    
    // Initialize search output buffer
    output = new int*[num_writers];
    for(int writer_id = 0; writer_id < num_writers; ++writer_id) 
        output[writer_id] = new int[MAX_MATCH_OUTPUT];
    
    cout << "Done" << endl;

    delete [] state;
    delete [] class_binding_key;
}

void search(vector<int> &writer_subset, uint8_t *search_query) {
    auto start = clock_start();
    size_t temp;

#ifdef SEARCH_EFFICIENCY
    PEKS_AggKey cp[RECURSIVE_LEVEL];
    for(int k = 0; k < RECURSIVE_LEVEL; ++k) {
        // cout << "Parsing Partition Token Level: " << k << endl;
        mpz_init(cp[k].k1);
        memcpy(&temp, search_query, sizeof(size_t));
        search_query += sizeof(size_t);
        mpz_import(cp[k].k1, temp, 1, 1, 0, 0, search_query);
        search_query += temp;
        element_init_G1(cp[k].k2, pairing);
        temp = element_from_bytes(cp[k].k2, search_query);
        search_query += temp;
        element_init_G1(cp[k].k3, pairing);
        temp = element_from_bytes(cp[k].k3, search_query);
        search_query += temp;
    }
#else 
    // Parse partition-matching search token
    PEKS_AggKey cp;
    mpz_init(cp.k1);
    memcpy(&temp, search_query, sizeof(size_t));
    search_query += sizeof(size_t);
    mpz_import(cp.k1, temp, 1, 1, 0, 0, search_query);
    search_query += temp;
    element_init_G1(cp.k2, pairing);
    temp = element_from_bytes(cp.k2, search_query);
    search_query += temp;
    element_init_G1(cp.k3, pairing);
    temp = element_from_bytes(cp.k3, search_query);
    search_query += temp;
#endif 
    // Parse keyword-matching search token
#ifdef WRITER_EFFICIENCY
    int n;
    memcpy(&n, search_query, sizeof(int));
    search_query += sizeof(int);
    
    PEKS_AggKey *cw = new PEKS_AggKey[n];
    for(int k = 0; k < n; ++k) {
        mpz_init(cw[k].k1);
        memcpy(&temp, search_query, sizeof(size_t));
        search_query += sizeof(size_t);
        mpz_import(cw[k].k1, temp, 1, 1, 0, 0, search_query);
        search_query += temp;
        element_init_G1(cw[k].k2, pairing);
        temp = element_from_bytes(cw[k].k2, search_query);
        search_query += temp;
        element_init_G1(cw[k].k3, pairing);
        temp = element_from_bytes(cw[k].k3, search_query);
        search_query += temp;
        cw[k].eepoch.assign(search_query, search_query + DEPTH_EPOCH_TREE);
        search_query += DEPTH_EPOCH_TREE;
    }
#else 
    PEKS_AggKey cw;
    mpz_init(cw.k1);
    memcpy(&temp, search_query, sizeof(size_t));
    search_query += sizeof(size_t);
    mpz_import(cw.k1, temp, 1, 1, 0, 0, search_query);
    search_query += temp;
    element_init_G1(cw.k2, pairing);
    temp = element_from_bytes(cw.k2, search_query);
    search_query += temp;
    element_init_G1(cw.k3, pairing);
    element_from_bytes(cw.k3, search_query);
#endif 
    vector<future<void>> threads;
    ThreadPool pool(MAX_THREADS_SEARCH);
    
#ifdef ENABLE_SEPARATE_SEARCH
    vector<int> duplicated_writer_subset;

    for(int writer_id: writer_subset)  
        duplicated_writer_subset.push_back(writer_id);
    
    for(int t = 0; t < MAX_THREADS_SEARCH; ++t) {
#ifdef WRITER_EFFICIENCY
        threads.push_back(pool.enqueue([t, &n, &cp, &cw, &duplicated_writer_subset, &writer_subset]() {
#else 
        threads.push_back(pool.enqueue([t, &cp, &cw, &duplicated_writer_subset, &writer_subset]() {
#endif 
            int writer_id;
            bool found; 
            string paddr;
            SHA512_CTX sha512;
            char addr[21];
            unsigned char m[37];
            unsigned char search_token[32];
            unsigned char tmp[64];
            
            while(!duplicated_writer_subset.empty()) {
                mtx.lock();
                if(!duplicated_writer_subset.empty()) {
                    writer_id = duplicated_writer_subset.back();
                    duplicated_writer_subset.pop_back();
                }
                else {
                    mtx.unlock();
                    break;
                }
                cout << "Looking up on the database of writer " << (writer_id+1) << "..." << endl; 
                mtx.unlock();
#ifdef SEARCH_EFFICIENCY
                paddr = "";
                for(int l = 0; l < RECURSIVE_LEVEL; ++l) {
                    found = false; 
                    for(PEKS_Token &eptkn: PTkn[writer_id][paddr]) {
                        bool r = HICKAE_Decrypt(writer_subset, writer_id, cp[l], eptkn, (unsigned char*)m);
                        if(r == true) {
                            // cout << "Matched found at partition: ";
                            // Convert partition tag to a string in hex
                            found = true;
                            memset(addr, 0, sizeof(addr));
                            for (int j = 0; j < 10; ++j) 
                                sprintf(addr+j*2, "%02x", m[j+5]);            
                            paddr.assign(addr, addr + 20);
                            // cout << paddr << endl;
                            // For measuring performance in the worst case, comment out the following break command
                            // break;
                        }
                    }
                    if(!found) break;
                }
#else 
                found = false; 

                for(PEKS_Token &eptkn: PTkn[writer_id][""]) {
                    bool r = HICKAE_Decrypt(writer_subset, writer_id, cp, eptkn, (unsigned char*)m);
                    if(r == true) {
                        // cout << "Matched found at partition: ";
                        // Convert partition tag to a string in hex
                        found = true;
                        memset(addr, 0, sizeof(addr));
                        for (int j = 0; j < 10; ++j) 
                            sprintf(addr+j*2, "%02x", m[j+5]);            
                        paddr.assign(addr, addr + 20);
                        // cout << paddr << endl;
                        // For measuring performance in the worst case, comment out the following break command
                        // break;
                    }
                }
#endif 

#ifdef WRITER_EFFICIENCY
                if(found) {
                    found = false;
                    vector<int> matches;
                    int k = 0;
                    bool r;

                    for(Encrypted_Search_Token &ewtkn: WTkn[writer_id][paddr]) {
                        r = false;
                        for(int i = 0; i < n; ++i) {
                            if(ewtkn.data.find(cw[i].eepoch) != ewtkn.data.end()) {
                                r = HICKAE_Decrypt(writer_subset, writer_id, cw[i], ewtkn.data[cw[i].eepoch], (unsigned char*)m);
                                break;
                            }
                        }
                        if(r == true) {
                            // cout << "Found DSSE Token: ";
                            // for(int i = 0; i < 32; ++i) 
                            //     cout << (int)m[i+5] << " ";
                            // cout << endl;
                            matches.push_back(k);
                            // For measuring performance in the worst case, comment out the following break command
                            // break;
                        }
                        ++k;
                    }

                    // Find the match corresponding to the latest update of the queried keyword
                    int latest_match = -1;
                    for(int i = 0; i < matches.size(); ++i) {
                        if(matches[i] > latest_match) {
                            latest_match = matches[i];
                        }
                    }

                    if(latest_match >= 0) {
                        found = true;
                        for(int i = 0; i < n; ++i) {
                            if(WTkn[writer_id][paddr][latest_match].data.find(cw[i].eepoch) != WTkn[writer_id][paddr][latest_match].data.end()) {
                                HICKAE_Decrypt(writer_subset, writer_id, cw[i], WTkn[writer_id][paddr][latest_match].data[cw[i].eepoch], (unsigned char*)m);
                                break;
                            }
                        }

                        memcpy(search_token, m + 5, 32);

                        // Then clear outdated search tokens to prevent augmenting search index size
                        for(int match: matches) {
                            if(match != latest_match) {
                                WTkn[writer_id][paddr].erase(WTkn[writer_id][paddr].begin() + match);
                            }
                        }
                    }
                }
#else 
                if(found) {
                    found = false;
                    vector<int> matches;
                    int k = 0;
                    for(PEKS_Token &ewtkn: WTkn[writer_id][paddr]) {
                        bool r = HICKAE_Decrypt(writer_subset, writer_id, cw, ewtkn, (unsigned char*)m);
                        if(r == true) {
                            // cout << "Found DSSE Token: ";
                            // for(int i = 0; i < 32; ++i) 
                            //     cout << (int)m[i+5] << " ";
                            // cout << endl;
                            matches.push_back(k);
                            // For measuring performance in the worst case, comment out the following break command
                            // break;
                        }
                        ++k;
                    }

                    // Find the match corresponding to the latest update of the queried keyword
                    int latest_match = -1;
                    for(int i = 0; i < matches.size(); ++i) {
                        if(matches[i] > latest_match) {
                            latest_match = matches[i];
                        }
                    }

                    // If a match is found
                    if(latest_match >= 0) {
                        // Mark as found and point to the newest DSSE search token
                        found = true;
                        HICKAE_Decrypt(writer_subset, writer_id, cw, WTkn[writer_id][paddr][latest_match], (unsigned char*)m);
                        memcpy(search_token, m + 5, 32);

                        // Then clear outdated search tokens to prevent augmenting search index size
                        for(int match: matches) {
                            if(match != latest_match) {
                                WTkn[writer_id][paddr].erase(WTkn[writer_id][paddr].begin() + match);
                            }
                        }
                    }
                }
#endif 
                if(found) {
                    int file_id;
                    int count = 0;
                    // cout << "Keyword appears in: ";
                    // cout << "Writer " << (writer_id + 1) << ": ";
                    while(1) {
                        SHA512_Init(&sha512);
                        SHA512_Update(&sha512, search_token, 16);
                        SHA512_Final(tmp, &sha512);

                        memset(addr, 0, sizeof(addr));
                        for (int i = 0; i < 10; ++i) 
                            sprintf(addr+i*2, "%02x", tmp[i]);
                        
                        if (EDTkn[writer_id].find(addr) != EDTkn[0].end())
                        {
                            DSSE_Token value;   
                            memcpy(value, EDTkn[writer_id][addr], sizeof(DSSE_Token));

                            for(int i = 0; i < 37; ++i) value[i] ^= tmp[i+10];

                            memcpy(&output[writer_id][count+1], value + 1, sizeof(int));
                            count++;

                            // memcpy(&file_id, value + 1, sizeof(int));
                            // cout << file_id << " ";
                            
                            memcpy(search_token, (uint8_t*)value + 5, 32);
                        }
                        else break;
                    }
                    output[writer_id][0] = count;
                    // memcpy(output[writer_id], &count, sizeof(int));
                    // cout << endl;
                }
                else { 
                    output[writer_id][0] = 0; 
                    // cout << "no matched results." << endl;
                }
            }
        }));
    }
    joinNclean(threads);
#else 
    unsigned char m[37];
    int count;

    for(int writer_id: writer_subset) {
        cout << "Looking up on the database of writer " << (writer_id+1) << "..." << endl; 
        count = 0;

        // cout << "ETTkn size: " << ETTkn[writer_id].size() << endl;
        
        int num_threads;
        int per_thread;
        string paddr = "";
        
#ifdef SEARCH_EFFICIENCY
        for(int l = 0; l < RECURSIVE_LEVEL; ++l) {
            found = false; 
            if(PTkn[writer_id][paddr].size() < MAX_THREADS_SEARCH) {
                per_thread = 1;
                num_threads = PTkn[writer_id][paddr].size();
            } else {
                per_thread = PTkn[writer_id][paddr].size()/MAX_THREADS_SEARCH;
                num_threads = MAX_THREADS_SEARCH;
            }

            for(int t = 0; t < num_threads; ++t) {
                threads.push_back(pool.enqueue([l, t, per_thread, &writer_subset, &writer_id, &cp, &paddr]() {
                    int start = t * per_thread;
                    int end;
                    unsigned char m[37];
                    if(t == MAX_THREADS_SEARCH-1) 
                        end = PTkn[writer_id][paddr].size();
                    else 
                        end = start + per_thread;

                    for(int k = start; k < end && found == false; ++k) {
                        bool r = HICKAE_Decrypt(writer_subset, writer_id, cp[l], PTkn[writer_id][paddr][k], (unsigned char*)m);
                        if(r == true) {
                            // cout << "Matched found at partition: ";
                            // Convert partition tag to a string in hex
                            found = true;
                            memset(addr, 0, sizeof(addr));
                            for (int j = 0; j < 10; ++j) 
                                sprintf(addr+j*2, "%02x", m[j+5]);            
                            paddr.assign(addr, addr + 20);
                            // cout << paddr << endl;
                            // For measuring performance in the worst case, comment out the following break command
                            // break;
                        }
                    }
                }));
            }
            joinNclean(threads);
            if(!found) break;
        }
#else 
        found = false;

        if(PTkn[writer_id][""].size() < MAX_THREADS_SEARCH) {
            per_thread = 1;
            num_threads = PTkn[writer_id][""].size();
        } else {
            per_thread = PTkn[writer_id][""].size()/MAX_THREADS_SEARCH;
            num_threads = MAX_THREADS_SEARCH;
        }

        for(int t = 0; t < num_threads; ++t) {
            threads.push_back(pool.enqueue([t, per_thread, &writer_subset, &writer_id, &cp, &paddr]() {
                int start = t * per_thread;
                int end;
                unsigned char m[37];
                if(t == MAX_THREADS_SEARCH-1) 
                    end = PTkn[writer_id][""].size();
                else 
                    end = start + per_thread;

                for(int k = start; k < end && found == false; ++k) {
                    bool r = HICKAE_Decrypt(writer_subset, writer_id, cp, PTkn[writer_id][""][k], (unsigned char*)m);
                    if(r == true) {
                        // cout << "Matched found at partition: ";
                        // Convert partition tag to a string in hex
                        found = true;
                        memset(addr, 0, sizeof(addr));
                        for (int j = 0; j < 10; ++j) 
                            sprintf(addr+j*2, "%02x", m[j+5]);            
                        paddr.assign(addr, addr + 20);
                        // cout << paddr << endl;
                        // For measuring performance in the worst case, comment out the following break command
                        // break;
                    }
                }
            }));
        }
        joinNclean(threads);
        
        // cout << "Partition matching: " << boolalpha << found << endl;
        
        /*
        // Single-thread execution
        for(auto ettkn: ETTkn[writer_id]) {
            bool r = HICKAE_Decrypt(subset, 1, writer_id, ct, ettkn, m);
            if(r == true) {
                // cout << "Matched found at parition: ";
                // Convert partition tag to a string in hex
                for (int j = 0; j < 10; ++j) 
                    sprintf(tmp_in_hex+j*2, "%02x", m[j+5]);            
                paddr.assign(tmp_in_hex, tmp_in_hex + 20);
                // cout << paddr << endl;
                break;
            }
        }
        */

        // cout << "Partition size: " << EWTkn[writer_id][paddr].size() << endl;
#endif 
        if(found) {
            // cout << "Partition address: " << paddr << endl;
            found = false;
            // cout << "WTkn size: " << WTkn[writer_id][paddr].size() << endl;
            vector<int> matches[MAX_THREADS_SEARCH];
            
            int num_threads;
            int per_thread;

            if(WTkn[writer_id][paddr].size() < MAX_THREADS_SEARCH) {
                per_thread = 1;
                num_threads = WTkn[writer_id][paddr].size();
            } else {
                per_thread = WTkn[writer_id][paddr].size()/MAX_THREADS_SEARCH;
                num_threads = MAX_THREADS_SEARCH;
            }
            
            for(int t = 0; t < num_threads; ++t) {
                threads.push_back(pool.enqueue([t, per_thread, &writer_subset, &writer_id, &cw, &paddr, &matches]() {
                    int start = t * per_thread;
                    int end;
                    unsigned char m[37];
                    if(t == MAX_THREADS_SEARCH-1) 
                        end = WTkn[writer_id][paddr].size();
                    else 
                        end = start + per_thread;

                    for(int k = start; k < end; ++k) {
                        bool r = HICKAE_Decrypt(writer_subset, writer_id, cw, WTkn[writer_id][paddr][k], (unsigned char*)m);
                        if(r == true) {
                            // cout << "Found DSSE Token: ";
                            // for(int i = 0; i < 32; ++i) 
                            //     cout << (int)m[i+5] << " ";
                            // cout << endl;
                            matches[t].push_back(k);
                            // For measuring performance in the worst case, comment out the following break command
                            // break;
                        }
                    }
                }));
            }
            joinNclean(threads);

            // Find the match corresponding to the latest update of the queried keyword
            int latest_match = -1;
            for(int t = 0; t < MAX_THREADS_SEARCH; ++t) {
                for(int i = 0; i < matches[t].size(); ++i) {
                    // cout << "A match is found at index: " << matches[t][i] << endl;
                    if(matches[t][i] > latest_match) {
                        latest_match = matches[t][i];
                    }
                }
            }

            // cout << "The match at: " << latest_match << " is selected." << endl;

            // If a match is found
            if(latest_match >= 0) {
                // Mark as found and point to the newest DSSE search token
                found = true;
                HICKAE_Decrypt(writer_subset, writer_id, cw, WTkn[writer_id][paddr][latest_match], (unsigned char*)m);
                memcpy(search_token, m + 5, 32);

                // Then clear outdated search tokens to prevent augmenting search index size
                for(int t = 0; t < MAX_THREADS_SEARCH; ++t) {
                    for(int i = 0; i < matches[t].size(); ++i) {
                        if(matches[t][i] != latest_match) {
                            WTkn[writer_id][paddr].erase(WTkn[writer_id][paddr].begin() + matches[t][i]);
                        }
                    }
                }
            }
        }

        /*
        // Single-thread execution
        for(auto ewtkn: EWTkn[writer_id][paddr]) {
            bool r = HICKAE_Decrypt(subset, 1, writer_id, cw, ewtkn, m);
            if(r == true) {
                memcpy(search_token, m + 5, 32);
                // cout << "Found DSSE Token: ";
                // for(int i = 0; i < 32; ++i) 
                //     cout << (int)m[i+5] << " ";
                // cout << endl;
                break;
            }
        }
        */

        // unsigned char writer_secret_key[32];
        // prg.reseed((block*)"generaterwritersecretkeys", writer_id + 1);
        // prg.random_block((block*)writer_secret_key, 2);

        // unsigned char search_token[32];
        // prf((unsigned char *)seed.c_str(), seed.length(), writer_secret_key, search_token);

        // cout << "Keyword matching: " << boolalpha << found << endl;
        
        if(found) {
            int file_id;
            // cout << "Keyword appears in: ";
            // cout << "Writer " << (writer_id + 1) << ": ";
            while(1) {
                SHA512_Init(&sha512);
                SHA512_Update(&sha512, search_token, 16);
                SHA512_Final(tmp, &sha512);

                memset(addr, 0, sizeof(addr));
                for (int i = 0; i < 10; ++i) 
                    sprintf(addr+i*2, "%02x", tmp[i]);
                
                if (EDTkn[writer_id].find(addr) != EDTkn[0].end())
                {
                    DSSE_Token value;   
                    memcpy(value, EDTkn[writer_id][addr], sizeof(DSSE_Token));

                    for(int i = 0; i < 37; ++i) value[i] ^= tmp[i+10];

                    memcpy(&output[writer_id][count+1], value + 1, sizeof(int));
                    count++;
        
                    // memcpy(&file_id, value + 1, sizeof(int));
                    // cout << file_id << " ";
                    
                    memcpy(search_token, (uint8_t*)value + 5, 32);
                }
                else break;
            }
            output[writer_id][0] = count;
            // memcpy(output[writer_id], &count, sizeof(int));
            // cout << endl;
        }
        else { 
            output[writer_id][0] = 0; 
            // cout << "no matched results." << endl;
        }
    }
#endif 
    int total_matches = 0;
    for(int writer_id: writer_subset) {
        // cout << output[writer_id][0] << " matches found on the database of writer " << (writer_id + 1) << endl;
        total_matches += output[writer_id][0]; 
    }
    
    cout << "Total matches: " << total_matches << endl;
    
    zmq::message_t search_output((total_matches + writer_subset.size()) * sizeof(int));
    uint8_t *search_output_data = (uint8_t*)search_output.data();

    for(int writer_id: writer_subset) {
        memcpy(search_output_data, &output[writer_id][0], sizeof(int));
        search_output_data += sizeof(int);
        if(output[writer_id][0] > 0) {
            memcpy(search_output_data, output[writer_id] + 1, output[writer_id][0]*sizeof(int));
            search_output_data += output[writer_id][0]*sizeof(int);
        }
    }

    socket_server->send(search_output);

    cout << "Server search latency: " << time_from(start) << endl;
}

void update(uint8_t *update_query) {
    auto start = clock_start();

    int writer_id;
    memcpy(&writer_id, update_query, 4);
    update_query += 4;

    int num_updates;
    memcpy(&num_updates, update_query, 4);
    update_query += 4;

    // cout << "Writer ID: " << writer_id << ", #Updates: " << num_updates << endl;
#ifdef WRITER_EFFICIENCY
    size_t n;
    memcpy(&n, update_query, sizeof(size_t));
    update_query += sizeof(size_t);
#endif 
    char addr[21];

    for(int i = 0; i < num_updates; ++i) {
        // Update EDB
        addr[20] = 0;
        memcpy(addr, update_query, 20);   
        update_query += 20;

        // cout << "EDB addresss: ";
        // for(int i = 0; i < 20; ++i)
        //     cout << addr[i];
        // cout << endl;

        memcpy(EDTkn[writer_id][addr], update_query, 37);
        update_query += 37;
        
        // Update ETkn
        string paddr;
        paddr.assign(update_query, update_query + 20);
        update_query += 20;

        // cout << "paddr: " << paddr << endl;

        if(WTkn[writer_id][paddr].empty()) {
/*
#ifdef SEARCH_EFFICIENCY
            bool exist = false;
            for(int k = 1; k < RECURSIVE_LEVEL; ++k) {
                if(!exist) {
                    PEKS_Token eptkn;
                    element_init_G2(eptkn.c1, pairing);
                    element_init_G2(eptkn.c2, pairing);
                    element_init_G2(eptkn.c3, pairing);
                    // eptkn.c4 = new unsigned char[37];
                    
                    element_from_bytes(eptkn.c1, update_query);
                    update_query += 168;
                    element_from_bytes(eptkn.c2, update_query);
                    update_query += 168;
                    element_from_bytes(eptkn.c3, update_query);
                    update_query += 168;
                    memcpy(eptkn.c4, update_query, 37);
                    update_query += 37;
                    
                    paddr.assign(update_query, update_query + 20);
                    update_query += 20;

                    if(PTkn[writer_id][paddr].empty()) exist = false;
                    else exist = true;

                    PTkn[writer_id][paddr].push_back(eptkn);
                }
                else {
                    update_query += 561;
                }
            }
            
            if(!exist) {
                PEKS_Token eptkn;
                element_init_G2(eptkn.c1, pairing);
                element_init_G2(eptkn.c2, pairing);
                element_init_G2(eptkn.c3, pairing);
                // eptkn.c4 = new unsigned char[37];
                
                element_from_bytes(eptkn.c1, update_query);
                update_query += 168;
                element_from_bytes(eptkn.c2, update_query);
                update_query += 168;
                element_from_bytes(eptkn.c3, update_query);
                update_query += 168;
                memcpy(eptkn.c4, update_query, 37);
                update_query += 37;

                PTkn[writer_id][""].push_back(eptkn);
            }
            else {
                update_query += 541;
            }
        } else {
            update_query += 561 * RECURSIVE_LEVEL - 20;
        }
#else 
*/
            PEKS_Token eptkn; 
            element_init_G2(eptkn.c1, pairing);
            element_init_G2(eptkn.c2, pairing);
            element_init_G2(eptkn.c3, pairing);
            // eptkn.c4 = new unsigned char[37];
            
            element_from_bytes(eptkn.c1, update_query);
            update_query += 168;
            element_from_bytes(eptkn.c2, update_query);
            update_query += 168;
            element_from_bytes(eptkn.c3, update_query);
            update_query += 168;
            memcpy(eptkn.c4, update_query, 37);
            update_query += 37;

            PTkn[writer_id][paddr].push_back(eptkn);
            // cout << i << ". A new partition tag corresponding to " << paddr << " is added." << endl; 
        } else {
            update_query += 541;
        }
// #endif

#ifdef WRITER_EFFICIENCY
        Encrypted_Search_Token ewtkn;
        string p;
        for(int i = 0; i < n; ++i) {
            p.assign(update_query, update_query + DEPTH_EPOCH_TREE);
            update_query += DEPTH_EPOCH_TREE;
            element_init_G2(ewtkn.data[p].c1, pairing);
            element_init_G2(ewtkn.data[p].c2, pairing);
            element_init_G2(ewtkn.data[p].c3, pairing);
            
            element_from_bytes(ewtkn.data[p].c1, update_query);
            update_query += 168;
            element_from_bytes(ewtkn.data[p].c2, update_query);
            update_query += 168;
            element_from_bytes(ewtkn.data[p].c3, update_query);
            update_query += 168;
            memcpy(ewtkn.data[p].c4, update_query, 37);
            update_query += 37;
        }
        WTkn[writer_id][paddr].push_back(ewtkn);
#else 
        PEKS_Token ewtkn;   
        element_init_G2(ewtkn.c1, pairing);
        element_init_G2(ewtkn.c2, pairing);
        element_init_G2(ewtkn.c3, pairing);
        // ewtkn.c4 = new unsigned char[37];

        element_from_bytes(ewtkn.c1, update_query);
        update_query += 168;
        element_from_bytes(ewtkn.c2, update_query);
        update_query += 168;
        element_from_bytes(ewtkn.c3, update_query);
        update_query += 168;
        memcpy(ewtkn.c4, update_query, 37);
        update_query += 37;

        WTkn[writer_id][paddr].push_back(ewtkn);
#endif 
    }
    
    char *ack_msg = "ACK";
    zmq::message_t ack(strlen(ack_msg) + 1);
    memcpy(ack.data(), ack_msg, strlen(ack_msg) + 1);
    socket_server->send(ack);
    
    cout << "Server update latency: " << time_from(start) << endl;
}

void rebuild(uint8_t *rebuild_query) {
    auto start = clock_start();

    epoch += 1;     // increment epoch number 
    int writer_id;
    memcpy(&writer_id, rebuild_query, 4);
    rebuild_query += 4;

    int num_partitions;
    memcpy(&num_partitions, rebuild_query, 4);
    rebuild_query += 4;

    // cout << "Num partitions: " << num_partitions << endl;

    for(int i = 0; i < num_partitions; ++i) {
        string paddr;
        paddr.assign(rebuild_query, rebuild_query + 20);
        WTkn[writer_id][paddr].clear();

        rebuild_query += 20;
        int partition_size;
        memcpy(&partition_size, rebuild_query, 4);
        rebuild_query += 4;

        // cout << "Partition size: " << partition_size << endl;

        for(int j = 0; j < partition_size; ++j) {
#ifdef WRITER_EFFICIENCY    
            cout << "Rebuild is unnecessary in this configuration!" << endl; 
#else 
            PEKS_Token ewtkn;   
            element_init_G2(ewtkn.c1, pairing);
            element_init_G2(ewtkn.c2, pairing);
            element_init_G2(ewtkn.c3, pairing);
            // ewtkn.c4 = new unsigned char[37];

            element_from_bytes(ewtkn.c1, rebuild_query);
            rebuild_query += 168;
            element_from_bytes(ewtkn.c2, rebuild_query);
            rebuild_query += 168;
            element_from_bytes(ewtkn.c3, rebuild_query);
            rebuild_query += 168;
            memcpy(ewtkn.c4, rebuild_query, 37);
            rebuild_query += 37;

            WTkn[writer_id][paddr].push_back(ewtkn);
#endif 
        }
    }

    cout << "Server rebuild latency: " << time_from(start) << endl;
    
    char *ack_msg = "ACK";
    zmq::message_t ack(strlen(ack_msg) + 1);
    memcpy(ack.data(), ack_msg, strlen(ack_msg) + 1);
    socket_server->send(ack);
}

int main(int argc, char *argv[]) {

    cout << "===================== Initialization =====================" << endl;

    context_server = new zmq::context_t(1);
    socket_server  = new zmq::socket_t(*context_server, ZMQ_REP);    
    socket_server->bind("tcp://*:" + to_string(SERVER_PORT));

    // Default number of writers
    num_writers = 25;
    
    // Start epoch number
    epoch = 1; 

#ifdef WRITER_EFFICIENCY
    encoded_epoch = "";
    
    // For testing
    uint64_t start_epoch = 1; 
    
    for(int i = 1; i <= start_epoch - 1; ++i) {
        encoded_epoch = encode_epoch(encoded_epoch);
        epoch++;
    }

    cout << "Encoded epoch: " << encoded_epoch << endl;
#endif 

    if(argc > 1) {
        num_writers = atoi(argv[1]);
    }
    
    // Fast Initialization: HICKAE parameters
    HICKAE_Setup(num_writers);
    
    HICKAE_KeyGen();

    HICKAE_IGen(num_writers);

    HICKAE_Prep(num_writers);

    // Initialize writers' databases
    init(num_writers);

    vector<int> writer_subset;
    int writer_subset_size;

    // Waiting and process users' queries
    while(1) {
        zmq::message_t query;
        socket_server->recv(&query);
        uint8_t *query_data = (uint8_t*)query.data();
        zmq::message_t reply(4);

        switch(query_data[0]) {
            // Get #writers
            case 'G':
                memcpy(reply.data(), &num_writers, 4);
                socket_server->send(reply);
                break;
            // Search
            case 'S':  
                query_data++;
                memcpy(&writer_subset_size, query_data, sizeof(int));  
                if(writer_subset_size > num_writers) {
                    cout << "Invalid search query!!! There are no more than " << num_writers << " writers." << endl;
                    memcpy(reply.data(), "ERR", 4);
                    socket_server->send(reply);
                    continue;
                }
                writer_subset.clear();
                for(int writer_id = 0; writer_id < writer_subset_size; ++writer_id) 
                    writer_subset.push_back(writer_id);
                query_data += sizeof(int);
                search(writer_subset, query_data);
                break;
            // Update 
            case 'U':
                update(query_data + 1);
                break;
            // Rebuild
            case 'R':
                rebuild(query_data + 1);
                break;
            default:
                cout << "Wrong query syntax!!!" << endl;
                break;
        }
    }
    return 0;
}
