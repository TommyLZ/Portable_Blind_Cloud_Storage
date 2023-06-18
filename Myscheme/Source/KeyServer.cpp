
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
    // Generate and Store public-private key pair

    element_init_Zr(this->secret_key, pairing);
    element_init_G2(this->public_key, pairing);

    if (!key_pair_generated)
    {
        cout << "ready to store the key" << endl;
        element_random(this->secret_key);
        element_pow_zn(this->public_key, g, this->secret_key);

        // 保存密钥到文件
        save_key_to_file(this->secret_key, "../Store/secret_key.bin");
        save_key_to_file(this->public_key, "../Store/public_key.bin");

        key_pair_generated = true;
    }
    else
    {
        cout << "ready to load the key" << endl;
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
    // string filename = "../Store/Cred_ks.txt";
    // // Check if the file exists
    // std::ifstream fileCheck(filename);
    // bool fileExists = fileCheck.good();
    // fileCheck.close();

    // if (fileExists)
    // {
    //     // If the file exists, clear the file
    //     std::ofstream clearFile(filename, std::ios::trunc);
    //     clearFile.close();
    // }

    // ofstream out(filename, ios::app);

    // if (out.is_open())
    // {
    //     out << "user_identity:" << ID_u
    //         << "    credential:" << cred_ks.substr(0, secureParam / 4);
    // }

    // out.close();

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

    string ID_u_str = ID_u;
    if (!outFile.is_open())
    {
        cout << "Error opening file for writing." << endl;
    }

    int ID_u_strLength = ID_u_str.length();
    outFile.write(reinterpret_cast<char *>(&ID_u_strLength), sizeof(int));
    outFile.write(ID_u_str.c_str(), ID_u_strLength);

    int credLength = cred_ks.substr(0, secureParam/4).length();
    outFile.write(reinterpret_cast<char *>(&credLength), sizeof(int));
    outFile.write(cred_ks.substr(0, secureParam/4).c_str(), credLength);

    outFile.close();

    cout << "You have successfully registered with the key server!" << endl;
}

void KeyServer::authenInGen_KS(string &EM_KS, string &ctx_dsk, string &rho_u, CryptoPP::byte *iv)
{
    // ifstream in("../Store/Cred_ks.txt");
    // string ID_u_str;
    // string cred_KS;

    // in >> ID_u_str;
    // in >> cred_KS;

    string filename = "../Store/Cred_ks.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    int ID_uLength;
    inFile.read(reinterpret_cast<char *>(&ID_uLength), sizeof(int));
    char *ID_u_char = new char[ID_uLength + 1];
    inFile.read(ID_u_char, ID_uLength);
    ID_u_char[ID_uLength] = '\0';
    string ID_u_str(ID_u_char);

    int credLength;
    inFile.read(reinterpret_cast<char *>(&credLength), sizeof(int));
    char *cred_ks_char = new char[credLength + 1];
    inFile.read(cred_ks_char, credLength);
    cred_ks_char[credLength] = '\0';
    string cred_KS(cred_ks_char);

    inFile.close();

    ID_u_str = ID_u_str.substr(ID_u_str.find(':') + 1, ID_u_str.size());
    cred_KS = cred_KS.substr(cred_KS.find(':') + 1, cred_KS.size());

    authentication(ID_u_str, cred_KS, EM_KS, iv);

    // string filename = "../Store/Cred_ks.txt";
    // ofstream out(filename, ios::app);
    // if (out.is_open())
    // {
    //     out << "    ctx_dsk:" << ctx_dsk
    //         << "    rho_u:" << rho_u.substr(0, secureParam / 4);
    // }
    // out.close();

    ofstream outFile(filename, ios::binary | ios::app);

    if (!outFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    cout << "ctx_dsk when storing: " << ctx_dsk << endl;
    cout << "ctx_dsk when storing: " << ctx_dsk << endl;
    cout << "ctx_dsk when storing: " << ctx_dsk << endl;
    int ctx_dskLength = ctx_dsk.length();
    outFile.write(reinterpret_cast<char *>(&ctx_dskLength), sizeof(int));
    outFile.write(ctx_dsk.c_str(), ctx_dskLength);
    cout << "the length of ctx_dsk before storing: " << ctx_dskLength << endl;

    int rho_uLength = rho_u.length();
    outFile.write(reinterpret_cast<char *>(&rho_uLength), sizeof(int));
    outFile.write(rho_u.c_str(), rho_uLength);

    outFile.close();

    cout << "You have successfully registered with the key server!" << endl;
}


void KeyServer::authenInRetrieve_KS(string& ctx_dsk, string& rho_u, string& EM_KS, CryptoPP::byte* iv)
{
    // string filename = "../Store/Cred_ks.txt";
    // ifstream in(filename);
    // string ID_u_str;
    // string cred_KS;

    // in >> ID_u_str;
    // in >> cred_KS;
    // in >> ctx_dsk;
    // in >> rho_u;

    string filename = "../Store/Cred_ks.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    int ID_uLength;
    inFile.read(reinterpret_cast<char *>(&ID_uLength), sizeof(int));
    char *ID_u_char = new char[ID_uLength + 1];
    inFile.read(ID_u_char, ID_uLength);
    ID_u_char[ID_uLength] = '\0';
    string ID_u_str(ID_u_char);

    int credLength;
    inFile.read(reinterpret_cast<char *>(&credLength), sizeof(int));
    char *cred_ks_char = new char[credLength + 1];
    inFile.read(cred_ks_char, credLength);
    cred_ks_char[credLength] = '\0';
    string cred_KS(cred_ks_char);

    int ctx_dskLength;
    inFile.read(reinterpret_cast<char *>(&ctx_dskLength), sizeof(int));
    char *ctx_dsk_char = new char[ctx_dskLength + 1];
    inFile.read(ctx_dsk_char, ctx_dskLength);
    ctx_dsk_char[ctx_dskLength] = '\0';
    ctx_dsk = ctx_dsk_char;
    cout << "the length of ctx_dsk after read: " << ctx_dskLength << endl;
    cout << "ctx_dsk after read: " << ctx_dsk << endl;

    int rho_uLength;
    inFile.read(reinterpret_cast<char *>(&rho_uLength), sizeof(int));
    char *rho_u_char = new char[rho_uLength + 1];
    inFile.read(rho_u_char, rho_uLength);
    rho_u_char[rho_uLength] = '\0';
    rho_u = rho_u_char;

    inFile.close();

    // ID_u_str = ID_u_str.substr(ID_u_str.find(':') + 1, ID_u_str.size());
    // cred_KS = cred_KS.substr(cred_KS.find(':') + 1, cred_KS.size());

    authentication(ID_u_str, cred_KS, EM_KS, iv);

    // ctx_dsk = ctx_dsk.substr(ctx_dsk.find(':') + 1, ctx_dsk.size());
    // rho_u = rho_u.substr(rho_u.find(':') + 1, rho_u.size());
}