#pragma once

#include <cryptopp/config.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

class KeyServer
{
private:
    element_t secret_key;

public:
    element_t public_key;

    KeyServer();

    void save_key_to_file(element_t key, const char* filename);
    void load_key_from_file(element_t key, const char* filename);

    void hardenPassword(element_t &beta, element_t &alpha);
    
    void store(char* ID_u, string& cred_ks );

    void authenInGen_KS(string& EM, string& ctx_dsk, string& rho, CryptoPP::byte* iv);

    void authenInRetrieve_KS(string& ctx_dsk, string& rho_u, string& EM_KS, CryptoPP::byte* iv);
};