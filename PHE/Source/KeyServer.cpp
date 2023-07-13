#include "KeyServer.h"
#include "PublicParam.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <pbc/pbc.h>
using namespace std;

extern pairing_t pairing;
extern element_t g;
extern double key_running_time;

static bool key_pair_generated = false;

KeyServer::KeyServer()
{
    auto start = chrono::high_resolution_clock::now();

    // Generate, store and load public-private key pair
    element_init_Zr(this->secret_key, pairing);
    element_init_G1(this->public_key, pairing);

    if (!key_pair_generated)
    {
        // Generate the key pair
        element_random(this->secret_key);
        element_pow_zn(this->public_key, g, this->secret_key);
        // element_printf("public_key: %B\n", this->public_key);

        this->nr = randomGeneration(secureParam);

        // Store the key pair
        save_to_file(this->secret_key, "../Store/ks_secret_key.bin");
        save_to_file(this->public_key, "../Store/ks_public_key.bin");
        save_State(this->nr, "../Store/ks_state.bin");

        // Set a tag to control one-time generation
        key_pair_generated = true;
    }
    else
    {
        load_from_file(this->secret_key, "../Store/ks_secret_key.bin");
        load_from_file(this->public_key, "../Store/ks_public_key.bin");
        this->nr = load_State("../Store/ks_state.bin");
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

Integer KeyServer::getnr()
{  
    auto start = chrono::high_resolution_clock::now();

    return this->nr;

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

void KeyServer::hardenPassword(element_t &b, element_t &a)
{
    auto start = chrono::high_resolution_clock::now();
    
    element_pow_zn(b, a, this->secret_key);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

void KeyServer::encrypt(element_t& c0, element_t& c1) {
    auto start = chrono::high_resolution_clock::now();

    string input0_str = Integer_to_string(this->nr) + "0";
    char* input0 = new char [input0_str.size() + 1];
    strcpy(input0, input0_str.c_str());

    string input1_str = Integer_to_string(this->nr) + "1";
    char* input1 = new char [input1_str.size() + 1];
    strcpy(input1, input1_str.c_str());

    // The key server computes hr0 and hr1.
    element_t hr0;
    element_init_G1(hr0, pairing);
    element_t hr1;
    element_init_G1(hr1, pairing);
    element_from_hash(hr0, input0, strlen(input0));
    element_from_hash(hr1, input1, strlen(input1));

    // Generate the c0 and c1.
    element_pow_zn(c0, hr0, this->secret_key);
    element_pow_zn(c1, hr1, this->secret_key);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

void KeyServer::decrypt(element_t& c1, element_t& c0) {
    auto start = chrono::high_resolution_clock::now();

    string input0_str = Integer_to_string(this->nr) + "0";
    char* input0 = new char [input0_str.size() + 1];
    strcpy(input0, input0_str.c_str());

    string input1_str = Integer_to_string(this->nr) + "1";
    char* input1 = new char [input1_str.size() + 1];
    strcpy(input1, input1_str.c_str());

    // The key server computes hr0, hr1.
    element_t hr0;
    element_init_G1(hr0, pairing);
    element_t hr1;
    element_init_G1(hr1, pairing);
    element_from_hash(hr0, input0, strlen(input0));
    element_from_hash(hr1, input1, strlen(input1));

    element_t tmp0;
    element_init_G1(tmp0, pairing);
    element_pow_zn(tmp0, hr0, this->secret_key);

    if (!element_cmp(tmp0, c0)) {
        cout << "The key server verifies!" << endl;
    }
    else {
        return ;
    }
    
    element_pow_zn(c1, hr1, this->secret_key);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();

    cout << "The key server running time is: " << key_running_time <<  endl;
}