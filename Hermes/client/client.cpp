#include <time.h>
#include <chrono>
#include <vector>
#include <zmq.hpp>
#include <iostream>
#include <sys/time.h>
#include <openssl/sha.h>
#include <zmq.hpp>
#include <emp-tool/emp-tool.h>
#include <emp-agmpc/emp-agmpc.h>
#include "gmp.h"
#include "utils.h"
#include "config.hpp"
#include "hickae.hpp"

using namespace std;

zmq::context_t *context_client;
zmq::socket_t  *socket_client;
PRG            prg; 
unsigned char  search_token[32];
int            num_writers;
unordered_map<string, uint64_t> *state;
uint64_t       epoch;
string         encoded_epoch;
mutex          mtx_pa, mtx_kw;

void init_sys() {
    // Setup
    HICKAE_Setup(num_writers);
    // Keygen
    HICKAE_KeyGen();
    // Writers execute IGen
    HICKAE_IGen(num_writers);
    // Reader executes Prep
    HICKAE_Prep(num_writers);
    cout << "Finished reader and writers setup" << endl;
}

void search(vector<int> &writer_subset, string &keyword) {
    auto start = clock_start();

#ifdef SEARCH_EFFICIENCY
    // Create partition-matching search token
    int num_partitions = NUM_PARTITIONS;

    PEKS_AggKey cp[RECURSIVE_LEVEL];
    array<uint64_t, 2> hash_value = mm_hash((uint8_t*)keyword.c_str(), keyword.length());
    uint64_t pid = ((hash_value[0] % num_partitions) << 2) | RECURSIVE_LEVEL;
    HICKAE_Extract(writer_subset, (char*)to_string(pid).c_str(), &cp[RECURSIVE_LEVEL - 1]);
    
    for(int k = 1; k < RECURSIVE_LEVEL; ++k) {
        num_partitions /= PARTITION_SIZE;
        hash_value = mm_hash((uint8_t*)&pid, sizeof(pid));
        pid = ((hash_value[0] % num_partitions) << 2) | (RECURSIVE_LEVEL - k); 
        // cout << "Partition ID Level " << k << ": " << pid << endl; 
        HICKAE_Extract(writer_subset, (char*)to_string(pid).c_str(), &cp[RECURSIVE_LEVEL - 1 - k]);
    }
#else 
    PEKS_AggKey cp;
    array<uint64_t, 2> hash_value = mm_hash((uint8_t*)keyword.c_str(), keyword.length());
    uint64_t pid = hash_value[0] % MAX_PARTITIONS;
    HICKAE_Extract(writer_subset, (char*)to_string(pid).c_str(), &cp);
#endif 
    
    // Create keyword-matching search token
#ifdef WRITER_EFFICIENCY
    vector<string> children_epochs;
    string padded_encoded_epoch = encoded_epoch;
    padded_encoded_epoch.insert(padded_encoded_epoch.end(), DEPTH_EPOCH_TREE - padded_encoded_epoch.size(), '0');
    children_epochs.push_back(padded_encoded_epoch);

    for(int i = encoded_epoch.length() - 1; i >= 0; --i) {
        string temp = encoded_epoch.substr(0, i);
        temp.insert(temp.end(), DEPTH_EPOCH_TREE - temp.size(), '0');
        children_epochs.push_back(temp);
    }
    
    /*
    cout << "Create keys with: " << endl;
    for(int i = 0; i < children_epochs.size(); ++i) {
        cout << children_epochs[i] << endl;
    }
    */
    
    PEKS_AggKey *cw = new PEKS_AggKey[children_epochs.size()];
    string *id = new string[children_epochs.size()];

    for(int i = 0; i < children_epochs.size(); ++i) {
        cw[i].eepoch = children_epochs[i];
        id[i] = keyword + children_epochs[i];
    }

    HICKAE_Extract(writer_subset, id, cw, children_epochs.size());
#else 
    string id;
    id = keyword + to_string(epoch);
    PEKS_AggKey cw;
    HICKAE_Extract(writer_subset, (char*)id.c_str(), &cw);
#endif 

    cout << "Time to create search query: " << time_from(start) << endl;

    // Send search query
    size_t temp;

#ifdef SEARCH_EFFICIENCY
    uint8_t cp_bytes[MAX_TOKEN_SIZE * RECURSIVE_LEVEL];
    size_t  cp_size = 0;

    for(int i = 0; i < RECURSIVE_LEVEL; ++i) {
        mpz_export(cp_bytes + cp_size + sizeof(size_t), &temp, 1, 1, 0, 0, cp[i].k1);
        memcpy(cp_bytes + cp_size, &temp, sizeof(size_t));
        cp_size += sizeof(size_t);
        cp_size += temp;
        temp = element_to_bytes(cp_bytes + cp_size, cp[i].k2);
        cp_size += temp;
        temp = element_to_bytes(cp_bytes + cp_size, cp[i].k3);
        cp_size += temp;
    }
    // cout << "cp_size: " << cp_size << endl;
#else 
    uint8_t cp_bytes[MAX_TOKEN_SIZE];
    size_t cp_size = sizeof(size_t);
    mpz_export(cp_bytes + cp_size, &temp, 1, 1, 0, 0, cp.k1);
    memcpy(cp_bytes, &temp, sizeof(size_t));
    cp_size += temp;
    temp = element_to_bytes(cp_bytes + cp_size, cp.k2);
    cp_size += temp;
    temp = element_to_bytes(cp_bytes + cp_size, cp.k3);
    cp_size += temp;
#endif 

#ifdef WRITER_EFFICIENCY
    uint8_t *cw_bytes = new uint8_t[(MAX_TOKEN_SIZE + DEPTH_EPOCH_TREE) * children_epochs.size()];
    size_t cw_size = 0;
    for(int i = 0; i < children_epochs.size(); ++i) {
        mpz_export(cw_bytes + cw_size + sizeof(size_t), &temp, 1, 1, 0, 0, cw[i].k1);
        memcpy(cw_bytes + cw_size, &temp, sizeof(size_t));
        cw_size += sizeof(size_t);
        cw_size += temp;
        temp = element_to_bytes(cw_bytes + cw_size, cw[i].k2);
        cw_size += temp;
        temp = element_to_bytes(cw_bytes + cw_size, cw[i].k3);
        cw_size += temp;
        memcpy(cw_bytes + cw_size, cw[i].eepoch.c_str(), DEPTH_EPOCH_TREE);
        cw_size += DEPTH_EPOCH_TREE;
    }
    delete [] cw;
    delete [] id;
#else
    uint8_t cw_bytes[MAX_TOKEN_SIZE];
    size_t cw_size = sizeof(size_t);
    mpz_export(cw_bytes + cw_size, &temp, 1, 1, 0, 0, cw.k1);
    memcpy(cw_bytes, &temp, sizeof(size_t));
    cw_size += temp;
    temp = element_to_bytes(cw_bytes + cw_size, cw.k2);
    cw_size += temp;
    temp = element_to_bytes(cw_bytes + cw_size, cw.k3);
    cw_size += temp;
#endif 
#ifdef WRITER_EFFICIENCY
    zmq::message_t search_query(1 + sizeof(int) + cp_size + sizeof(int) + cw_size);
#else 
    zmq::message_t search_query(1 + sizeof(int) + cp_size + cw_size);
#endif 
    uint8_t *search_query_data = (uint8_t*)search_query.data();
    search_query_data[0] = 'S';
    int writer_subset_size = writer_subset.size();
    memcpy(search_query_data + 1, &writer_subset_size, sizeof(int));
    memcpy(search_query_data + 1 + sizeof(int), cp_bytes, cp_size);
#ifdef WRITER_EFFICIENCY
    int n = children_epochs.size();
    memcpy(search_query_data + 1 + sizeof(int) + cp_size, &n, sizeof(int)); 
    memcpy(search_query_data + 1 + sizeof(int) + cp_size + sizeof(int), cw_bytes, cw_size); 
#else 
    memcpy(search_query_data + 1 + sizeof(int) + cp_size, cw_bytes, cw_size); 
#endif 

    socket_client->send(search_query);
    
    // Receive search output
    zmq::message_t search_outcome;
    socket_client->recv(&search_outcome);
    uint8_t *search_outcome_data = (uint8_t*)search_outcome.data();

    // cout << "Received " << search_outcome.size() << " bytes from the server." << endl;

    cout << "Keyword " << "\"" << keyword << "\" appears in: " << endl;

    int file_id;
    int count = 0;

    for(int writer_id: writer_subset) {
        cout << "Writer " << (writer_id + 1) << ": ";
        memcpy(&count, search_outcome_data, sizeof(int));
        search_outcome_data += sizeof(int);
        if(count == 0) cout << "no matched documents." << endl;
        else {
            for(int k = 0; k < count; ++k) {
                memcpy(&file_id, search_outcome_data, sizeof(int));
                cout << file_id << " ";
                search_outcome_data += sizeof(int);
            }
            cout << endl;
        }
    }
    cout << "End-to-end search latency: " << time_from(start) << endl;
}

void update(int writer_id, int file_id, int num_updates) {
    // Initialize states of existing keywords 
    // In real, this should be stored locally
    unordered_map<string, uint64_t> state;
    string user_database = to_string(writer_id+1) + ".txt";
    ifstream file("../database/" + user_database);

    string line;
    string keyword;

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

    size_t n = gamma_t.size();

    // cout << "n = " << n << endl;

    vector<future<void>> threads;
    ThreadPool pool(MAX_THREADS_UPDATE);

    int num_threads;
    int per_thread;

    if(gamma_t.size() < MAX_THREADS_UPDATE) {
        per_thread = 1;
        num_threads = gamma_t.size();
    } else {
        per_thread = gamma_t.size()/MAX_THREADS_UPDATE;
        num_threads = MAX_THREADS_UPDATE;
    }

    Encrypted_Search_Token ewtkn;
#endif

    while(getline(file, line)) {
        stringstream wss(line);
        wss >> keyword;
        istringstream iss(line.substr(keyword.length() + 1));
        state[keyword] = 0;
        int file_id;
        while(iss >> file_id) {
            state[keyword]++;
        }
    }
    file.close();

    // cout << "state[\"university\"]: " << state["university"] << endl;

    auto start = clock_start();
    
    ifstream updated_file("words.txt");
    unsigned char writer_secret_key[32];
    prg.reseed((block*)"generaterwritersecretkeys", writer_id+1);
    prg.random_block((block*)writer_secret_key, 2);

    unsigned char token[32];
    unsigned char prev_token[32];
    SHA512_CTX sha512;
    unsigned char tmp[SHA512_DIGEST_LENGTH];
    char addr[21];

#ifdef WRITER_EFFICIENCY
    zmq::message_t update_query(17 + (UPDATE_TOKEN_SIZE + (541 + DEPTH_EPOCH_TREE) * n) * num_updates);
#else 
    zmq::message_t update_query(9 + UPDATE_TOKEN_SIZE * num_updates);
#endif 
    uint8_t *update_query_data = (uint8_t*)update_query.data();
    update_query_data[0] = 'U';
    update_query_data += 1;
    memcpy(update_query_data, &writer_id, 4);
    update_query_data += 4;
    memcpy(update_query_data, &num_updates, 4);
    update_query_data += 4;
#ifdef WRITER_EFFICIENCY
    memcpy(update_query_data, &n, sizeof(size_t));
    update_query_data += sizeof(size_t);
#endif 
    for(int i = 0; i < num_updates && getline(updated_file, keyword); ++i) {
        
        // cout << "Keyword: " << keyword << endl;

        string seed;
        if(state[keyword] == 0) {
            memset(prev_token, 0, sizeof(prev_token));
        } 
        else {
            seed = keyword + to_string(state[keyword] - 1); 
            prf((unsigned char *)seed.c_str(), seed.length(), writer_secret_key, prev_token);
        }

        seed = keyword + to_string(state[keyword]); 
        prf((unsigned char *)seed.c_str(), seed.length(), writer_secret_key, token);
        
        SHA512_Init(&sha512);
        SHA512_Update(&sha512, token, 16);
        SHA512_Final(tmp, &sha512);

        // u_sse = (addr, value)
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

        // cout << "EDB addresss: ";
        // for(int i = 0; i < 20; ++i)
        //     cout << addr[i];
        // cout << endl;
        
        memcpy(update_query_data, addr, 20);
        update_query_data += 20;
        memcpy(update_query_data, value, 37);
        update_query_data += 37;
        
#ifdef SEARCH_EFFICIENCY
        int num_partitions = NUM_PARTITIONS;
        array<uint64_t, 2> hash_value = mm_hash((uint8_t*)keyword.c_str(), keyword.length());
        uint64_t pid = ((hash_value[0] % num_partitions) << 2) | RECURSIVE_LEVEL;

        unsigned char partition_tag[32];
        prf((unsigned char *)&pid, sizeof(pid), writer_secret_key, partition_tag);

        for (int j = 0; j < 10; ++j) 
            sprintf(addr+j*2, "%02x", partition_tag[j]);  

        string paddr;          
        paddr.assign(addr, addr + 20);

        memcpy(update_query_data, paddr.c_str(), 20);
        update_query_data += 20;

        /*
        for(int k = 1; k < RECURSIVE_LEVEL; ++k) {
            PEKS_Token eptkn;
            HICKAE_Encrypt(writer_id, (char*)to_string(pid).c_str(), partition_tag, &eptkn);

            element_to_bytes(update_query_data, eptkn.c1);
            update_query_data += 168;
            element_to_bytes(update_query_data, eptkn.c2);
            update_query_data += 168;
            element_to_bytes(update_query_data, eptkn.c3);
            update_query_data += 168;
            memcpy(update_query_data, eptkn.c4, 37);
            update_query_data += 37;

            num_partitions /= PARTITION_SIZE;
            hash_value = mm_hash((uint8_t*)&pid, sizeof(pid));
            pid = ((hash_value[0] % num_partitions) << 2) | (RECURSIVE_LEVEL - k);
            
            prf((unsigned char *)&pid, sizeof(pid), writer_secret_key, partition_tag);
            
            for (int j = 0; j < 10; ++j) 
                sprintf(addr+j*2, "%02x", partition_tag[j]);  

            paddr.assign(addr, addr + 20);

            memcpy(update_query_data, paddr.c_str(), 20);
            update_query_data += 20;
        }
        */
        PEKS_Token eptkn;
        HICKAE_Encrypt(writer_id, (char*)to_string(pid).c_str(), partition_tag, &eptkn);
        
        element_to_bytes(update_query_data, eptkn.c1);
        update_query_data += 168;
        element_to_bytes(update_query_data, eptkn.c2);
        update_query_data += 168;
        element_to_bytes(update_query_data, eptkn.c3);
        update_query_data += 168;
        memcpy(update_query_data, eptkn.c4, 37);
        update_query_data += 37;
#else 
        array<uint64_t, 2> hash_value = mm_hash((uint8_t*)keyword.c_str(), keyword.length());
        uint64_t pid = hash_value[0] % MAX_PARTITIONS;
        
        // Compute partition tag from writer's secret key 
        unsigned char partition_tag[32];
        prf((unsigned char *)&pid, sizeof(pid), writer_secret_key, partition_tag);
        
        // Convert partition tag to a string in hex
        for (int j = 0; j < 10; ++j) 
            sprintf(addr+j*2, "%02x", partition_tag[j]);         

        // cout << "Partition address: ";
        // for(int i = 0; i < 20; ++i)
        //     cout << addr[i];
        // cout << endl;

        string paddr;
        paddr.assign(addr, addr + 20);

        // cout << "paddr: " << paddr << endl;
        
        memcpy(update_query_data, paddr.c_str(), 20);
        update_query_data += 20;

        PEKS_Token eptkn;
        HICKAE_Encrypt(writer_id, (char*)to_string(pid).c_str(), partition_tag, &eptkn);

        element_to_bytes(update_query_data, eptkn.c1);
        update_query_data += 168;
        element_to_bytes(update_query_data, eptkn.c2);
        update_query_data += 168;
        element_to_bytes(update_query_data, eptkn.c3);
        update_query_data += 168;
        memcpy(update_query_data, eptkn.c4, 37);
        update_query_data += 37;
#endif 

#ifdef WRITER_EFFICIENCY

        for(int t = 0; t < num_threads; ++t) {
            threads.push_back(pool.enqueue([t, &ewtkn, &keyword, &token, &writer_id, &per_thread, &gamma_t]() {
                int start = t * per_thread;
                int end;
                if(t == MAX_THREADS_UPDATE-1) 
                    end = gamma_t.size();
                else 
                    end = start + per_thread;
                
                string id; 
                PEKS_Token ewtkn_data;

                for(int k = start; k < end; ++k) {
                    id = keyword + gamma_t[k];
                    HICKAE_Encrypt(writer_id, (char*)id.c_str(), token, &ewtkn_data);

                    mtx_kw.lock();
                    element_init_G2(ewtkn.data[gamma_t[k]].c1, pairing);
                    element_set(ewtkn.data[gamma_t[k]].c1, ewtkn_data.c1);
                    element_init_G2(ewtkn.data[gamma_t[k]].c2, pairing);
                    element_set(ewtkn.data[gamma_t[k]].c2, ewtkn_data.c2);
                    element_init_G2(ewtkn.data[gamma_t[k]].c3, pairing);
                    element_set(ewtkn.data[gamma_t[k]].c3, ewtkn_data.c3);
                    memcpy(ewtkn.data[gamma_t[k]].c4, ewtkn_data.c4, 37);
                    mtx_kw.unlock();   
                }
            }));
        }
        joinNclean(threads);
        
        for(int i = 0; i < gamma_t.size(); ++i) {
            memcpy(update_query_data, gamma_t[i].c_str(), DEPTH_EPOCH_TREE);
            update_query_data += DEPTH_EPOCH_TREE;
            element_to_bytes(update_query_data, ewtkn.data[gamma_t[i]].c1);
            update_query_data += 168;
            element_to_bytes(update_query_data, ewtkn.data[gamma_t[i]].c2);
            update_query_data += 168;
            element_to_bytes(update_query_data, ewtkn.data[gamma_t[i]].c3);
            update_query_data += 168;
            memcpy(update_query_data, ewtkn.data[gamma_t[i]].c4, 37);
            update_query_data += 37;
        }
#else 
        string id = keyword + to_string(epoch);

        PEKS_Token ewtkn;
        HICKAE_Encrypt(writer_id, (char*)id.c_str(), token, &ewtkn);
        
        element_to_bytes(update_query_data, ewtkn.c1);
        update_query_data += 168;
        element_to_bytes(update_query_data, ewtkn.c2);
        update_query_data += 168;
        element_to_bytes(update_query_data, ewtkn.c3);
        update_query_data += 168;
        memcpy(update_query_data, ewtkn.c4, 37);
        update_query_data += 37;
#endif 
        state[keyword]++;
    }
    updated_file.close();

    socket_client->send(update_query);

    cout << "Writer update latency: " << time_from(start) << endl;

    // Wait for reply from the server
    zmq::message_t update_reply;
    socket_client->recv(&update_reply);

    cout << "End-to-end update latency: " << time_from(start) << endl;
}

void rebuild() {
#ifdef WRITER_EFFICIENCY
    cout << "Rebuild is unnecessary in this configuration!" << endl; 
#else 
    auto start = clock_start();
    epoch += 1;     // increment epoch number 
    
    // For measuring performance
    vector<int> writer_subset {0}; // ~10k
    // vector<int> writer_subset {1}; // ~20k
    // vector<int> writer_subset {0, 1}; // ~30k
    // vector<int> writer_subset {0, 1, 2, 4}; // ~40k
    // vector<int> writer_subset {0, 1, 2, 3, 8}; // ~50k
    // vector<int> writer_subset {0, 1, 2, 3, 5}; // ~60k

    vector<future<void>> threads;
    ThreadPool pool(MAX_THREADS_REBUILD);
    
    for(int writer_id: writer_subset) {
        auto start = clock_start();
        
        unsigned char writer_secret_key[32];
        prg.reseed((block*)"generaterwritersecretkeys", writer_id+1);
        prg.random_block((block*)writer_secret_key, 2);
        string user_database = to_string(writer_id+1) + ".txt";
        // int num_keywords = count_lines("../database/" + user_database); 
        // cout << "#Keywords: " << num_keywords << endl;
        
        ifstream file("../database/" + user_database);
        string line, keyword;
        unordered_map<string, uint64_t> state;
        unordered_map<string, vector<PEKS_Token>> WTkn;
        set<string> partition_address;
        vector<string> keyword_set;
        
        while(getline(file, line)) {
            stringstream wss(line);
            wss >> keyword;
            istringstream iss(line.substr(keyword.length() + 1));
            state[keyword] = 0;
            int file_id;
            while(iss >> file_id) {
                state[keyword]++;
            }
            keyword_set.push_back(keyword);
        }

        int num_threads;
        int per_thread;

        if(keyword_set.size() < MAX_THREADS_REBUILD) {
            per_thread = 1;
            num_threads = keyword_set.size();
        } else {
            per_thread = keyword_set.size()/MAX_THREADS_REBUILD;
            num_threads = MAX_THREADS_REBUILD;
        }

        for(int t = 0; t < num_threads; ++t) {
            threads.push_back(pool.enqueue([t, per_thread, &keyword_set, &state, &writer_id, 
                                        &writer_secret_key, &partition_address, &WTkn]() {
                int start = t * per_thread;
                int end;
                if(t == MAX_THREADS_SEARCH-1) 
                    end = keyword_set.size();
                else 
                    end = start + per_thread;

                unsigned char current_token[32];
                char addr[21];

                for(int k = start; k < end; ++k) {
                    string keyword = keyword_set[k];
                    string seed = keyword + to_string(state[keyword] - 1); 
                    prf((unsigned char *)seed.c_str(), seed.length(), writer_secret_key, current_token);

                    string id = keyword + to_string(epoch);

                    PEKS_Token ewtkn;
                    HICKAE_Encrypt(writer_id, (char*)id.c_str(), current_token, &ewtkn);

                    array<uint64_t, 2> hash_value = mm_hash((uint8_t*)keyword.c_str(), keyword.length());

#ifdef SEARCH_EFFICIENCY
                    uint64_t pid = ((hash_value[0] % NUM_PARTITIONS) << 2) | RECURSIVE_LEVEL;
#else 
                    uint64_t pid = hash_value[0] % MAX_PARTITIONS;
#endif 
                    // Compute partition tag from writer's secret key 
                    unsigned char partition_tag[32];
                    prf((unsigned char *)&pid, sizeof(pid), writer_secret_key, partition_tag);

                    // Convert partition tag to a string in hex
                    for (int j = 0; j < 10; ++j) 
                        sprintf(addr+j*2, "%02x", partition_tag[j]);            
                    string paddr;
                    paddr.assign(addr, addr + 20);

                    mtx_pa.lock();
                    partition_address.insert(paddr);
                    mtx_pa.unlock();

                    mtx_kw.lock();
                    WTkn[paddr].push_back(ewtkn);
                    mtx_kw.unlock();
                }
            }));
        }

        joinNclean(threads);

        int num_elements = 0;
        for(string paddr: partition_address) { 
            num_elements += WTkn[paddr].size();
        }

        zmq::message_t rebuild_request(9 + num_elements*541 + partition_address.size()*24);
        unsigned char *rebuild_request_data = (unsigned char*)rebuild_request.data();
        rebuild_request_data[0] = 'R';
        rebuild_request_data += 1;
        memcpy(rebuild_request_data, &writer_id, sizeof(int));
        rebuild_request_data += 4;
        int num_partitions = partition_address.size();
        // cout << "Num partitions: " << num_partitions << endl;

        memcpy(rebuild_request_data, &num_partitions, sizeof(int));
        rebuild_request_data += 4;

        for(string paddr: partition_address) {
            memcpy(rebuild_request_data, paddr.c_str(), 20);
            rebuild_request_data += 20;
            int partition_size = WTkn[paddr].size();
            // cout << "Partition size: " << partition_size << endl;

            memcpy(rebuild_request_data, &partition_size, sizeof(int));
            rebuild_request_data += 4;

            for(PEKS_Token ewtkn: WTkn[paddr]) {
                element_to_bytes(rebuild_request_data, ewtkn.c1);
                rebuild_request_data += 168;
                element_to_bytes(rebuild_request_data, ewtkn.c2);
                rebuild_request_data += 168;
                element_to_bytes(rebuild_request_data, ewtkn.c3);
                rebuild_request_data += 168;
                memcpy(rebuild_request_data, ewtkn.c4, 37);
                rebuild_request_data += 37;
            }
        }
        socket_client->send(rebuild_request);

        // Wait for ACK
        zmq::message_t rebuild_reply;
        socket_client->recv(&rebuild_reply);

        cout << "Writer rebuild latency: " << time_from(start) << endl;
    }
    cout << "End-to-end rebuild latency: " << time_from(start) << endl;
#endif 
}

int main(int argc, char *argv[]) {
    cout << "===================== Initialization =====================" << endl;
    
    // Connect to the server 
    context_client = new zmq::context_t(1);
    socket_client = new zmq::socket_t(*context_client, ZMQ_REQ);
    string server_address = "tcp://127.0.0.1:" + to_string(SERVER_PORT);
    socket_client->connect(server_address);
    cout << "Connected to the server at the address " << server_address << endl;
    
    // Default number of writers
    num_writers = 25;

    // Start epoch number
    epoch = 1;
    
#ifdef WRITER_EFFICIENCY
    encoded_epoch = "";
    
    // For testing
    uint64_t start_epoch = 11; 
    
    for(int i = 1; i <= start_epoch - 1; ++i) {
        encoded_epoch = encode_epoch(encoded_epoch);
        epoch++;
    }

    cout << "Encoded epoch: " << encoded_epoch << endl;
#endif 
    
    // Get the number of writers from the server
    zmq::message_t msg_get_num_writers(1);
    *((uint8_t*)msg_get_num_writers.data()) = 'G';
    socket_client->send(msg_get_num_writers);

    zmq::message_t msg_reply_num_writers;
    socket_client->recv(&msg_reply_num_writers);
    memcpy(&num_writers, msg_reply_num_writers.data(), 4);

    // Initializing system
    init_sys();
    
    if(argc > 1) {
        if (strcmp(argv[1], "-s") == 0) { 
            // set default queried keyword
            string keyword = "university";
            if(argc > 2) 
                keyword = argv[2];
            int writer_subset_size = num_writers;
            if(argc > 3) 
                writer_subset_size = atoi(argv[3]);
            
            if(writer_subset_size > num_writers) {
                cout << "There are no more than " << num_writers << " writers." << endl;
                return 1;
            }

            // Execute search queries
            cout << "===================== Search query ======================" << endl;
            vector<int> writer_subset;
            for(int writer_id = 0; writer_id < writer_subset_size; ++writer_id) 
                writer_subset.push_back(writer_id);
            search(writer_subset, keyword);
        }
        else if(strcmp(argv[1], "-u") == 0) {
            // Search before update
            string keyword = "security";
            vector<int> writer_subset;
            for(int writer_id = 0; writer_id < num_writers; ++writer_id) 
                writer_subset.push_back(writer_id);
            search(writer_subset, keyword);
            
            // Execute update queries
            cout << "===================== Update query ======================" << endl;
            int num_updates = 25;
            if(argc > 2) 
                num_updates = atoi(argv[2]);
            update(0, 2025, num_updates);
            
            // Search after update
            search(writer_subset, keyword);
        }
        else if(strcmp(argv[1], "-r") == 0) {
            string keyword = "university";
            vector<int> writer_subset;
            for(int writer_id = 0; writer_id < num_writers; ++writer_id) 
                writer_subset.push_back(writer_id);
            search(writer_subset, keyword);
            // Execute rebuild queries
            cout << "===================== Rebuild query =====================" << endl;
            rebuild();
            // vector<int> writer_subset;
            // for(int writer_id = 0; writer_id < num_writers; ++writer_id) 
            //     writer_subset.push_back(writer_id);
            search(writer_subset, keyword);
        }
        else {
            cout << "Invalid syntax!!!" << endl;
            return 1;
        }
    }
    return 0;
}
