#pragma once

#include <iostream>
#include <cryptopp/config.h>
using namespace std;
using namespace CryptoPP;

class CloudServer
{

public:
    CloudServer();

    void store(char* ID_u, string& cred_cs, string& s_u);

    void authenInGen_CS(string& s_u, char* ID_u, string& EM_CS, CryptoPP::byte (&iv)[16]);

    void randomStore(string& gamma_u);

    void authenInRetrieve_CS(string& s_u, string& gamma_u, char* ID_u, string& EM_CS, CryptoPP::byte* iv_CS);
};