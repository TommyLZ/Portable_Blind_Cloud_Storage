#include "Client.h"
#include "PublicParam.h"

#include <iostream>
#include <cstring>
#include <sstream>
#include <pbc/pbc.h>
using namespace std;

extern pairing_t pairing;
extern element_t h;
extern double client_running_time;

Client::Client() {}

Client::Client(string &psw, string &id)
{   
    auto start = chrono::high_resolution_clock::now();

    this->psw = psw;
    this->id = id;

    element_init_Zr(this->r, pairing);
    element_random(this->r);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::blindPassword(element_t &a)
{
    auto start = chrono::high_resolution_clock::now();

    char *psw_char = new char[this->psw.size() + this->id.size() + 1];
    strcpy(psw_char, this->psw.c_str());
    strcat(psw_char, this->id.c_str());
    
    // Hash to G1
    element_from_hash(h, psw_char, strlen(psw_char));
    // Blindness
    element_pow_zn(a, h, this->r);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::CredentialGen(string& cred_cs, element_t& b, element_t& a, element_t& public_key)
{   
    auto start = chrono::high_resolution_clock::now();
    
    verify(b, a, public_key);

    element_t r_inverse;
    element_init_Zr(r_inverse, pairing);
    element_invert(r_inverse, this->r);

    element_t salt;
    element_init_G1(salt, pairing);
    element_pow_zn(salt, b, r_inverse);

    // Transform from element_t to string
    string salt_str;
    stringstream ss;
    int salt_len = element_length_in_bytes(salt);
    unsigned char *salt_bytes = new unsigned char[salt_len];
    element_to_bytes(salt_bytes, h);
    for (int i = 0; i < salt_len; i++)
    {
        ss << std::hex << (int)salt_bytes[i];
    }
    salt_str = ss.str();

    string input1 = this->psw + salt_str;
    cred_cs = sha256Hash(input1).substr(0, secureParam / 4);


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
    cout << "the client running time is: " << client_running_time << endl;
}
