
#include "KeyServer.h"
#include "PublicParam.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <stdlib.h>
#include <cryptopp/config.h>
#include <pbc/pbc.h>

extern pairing_t pairing;
extern element_t g;

using namespace std;
using namespace CryptoPP;

static bool key_pair_generated = false;

void KeyServer::save_key_to_file(element_t key, const char *filename)
{
    std::ofstream outfile(filename, std::ios::binary);
    size_t key_size = element_length_in_bytes(key);
    unsigned char key_bytes[key_size];
    element_to_bytes(key_bytes, key);
    outfile.write((char *)key_bytes, key_size);
    outfile.close();
}

void KeyServer::load_key_from_file(element_t key, const char *filename)
{
    std::ifstream infile(filename, std::ios::binary);
    infile.seekg(0, infile.end);
    size_t key_size = infile.tellg();
    infile.seekg(0, infile.beg);
    unsigned char key_bytes[key_size];
    infile.read((char *)key_bytes, key_size);
    element_from_bytes(key, key_bytes);
    infile.close();
}

KeyServer::KeyServer()
{
    // Generate, store and load public-private key pair

    element_init_Zr(this->secret_key, pairing);
    element_init_G2(this->public_key, pairing);

    if (!key_pair_generated)
    {
        // Generate the key pair
        element_random(this->secret_key);
        element_pow_zn(this->public_key, g, this->secret_key);

        // Store the key pair
        save_key_to_file(this->secret_key, "../Store/secret_key.bin");
        save_key_to_file(this->public_key, "../Store/public_key.bin");

        // Set a tag to control one-time generation
        key_pair_generated = true;
    }
    else
    {
        load_key_from_file(this->secret_key, "../Store/secret_key.bin");
        load_key_from_file(this->public_key, "../Store/public_key.bin");
    }
}

void KeyServer::hardenPassword(element_t &beta, element_t &alpha)
{
    // Hard or sign
    element_pow_zn(beta, alpha, this->secret_key);
}

void KeyServer::store(char *ID_u, string &cred_ks)
{
    string filename = "../Store/Cred_ks.bin";

    // Check if the file exists
    ifstream fileCheck(filename);
    bool fileExists = fileCheck.good();
    fileCheck.close();

    if (fileExists)
    {
        // If the file exists, clear the file
        std::ofstream clearFile(filename, ios::trunc);
        clearFile.close();
    }

    ofstream outFile(filename, ios::binary | ios::app);

    if (!outFile.is_open())
    {
        cout << "Error opening file for writing." << endl;
        return;
    }

    string ID_u_str = ID_u;
    writeToBin(outFile, ID_u_str);
    writeToBin(outFile, cred_ks.substr(0, secureParam / 4));

    outFile.close();
}

void KeyServer::authenInGen_KS(string &EM_KS, string &ctx_dsk, string &rho_u, CryptoPP::byte *iv)
{
    string filename = "../Store/Cred_ks.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
        return;
    }

    string ID_u_str;
    readFromBin(inFile, ID_u_str);

    string cred_KS;
    readFromBin(inFile, cred_KS);

    inFile.close();

    ID_u_str = ID_u_str.substr(ID_u_str.find(':') + 1, ID_u_str.size());
    cred_KS = cred_KS.substr(cred_KS.find(':') + 1, cred_KS.size());

    authentication(ID_u_str, cred_KS, EM_KS, iv);

    ofstream outFile(filename, ios::binary | ios::app);

    if (!outFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
        return;
    }

    writeToBin(outFile, ctx_dsk);
    writeToBin(outFile, rho_u);

    outFile.close();
}

void KeyServer::authenInRetrieve_KS(string &ctx_dsk, string &rho_u, string &EM_KS, CryptoPP::byte *iv)
{
    string filename = "../Store/Cred_ks.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
        return;
    }

    string ID_u_str;
    readFromBin(inFile, ID_u_str);
    string cred_KS;
    readFromBin(inFile, cred_KS);
    readFromBin(inFile, ctx_dsk);
    readFromBin(inFile, rho_u);

    inFile.close();

    authentication(ID_u_str, cred_KS, EM_KS, iv);
}