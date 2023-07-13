#include "Client.h"
#include "PublicParam.h"

#include <iostream>
#include <cstring>
#include <sstream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <pbc/pbc.h>
using namespace std;
using namespace CryptoPP;

extern pairing_t pairing;
extern element_t h;
extern double client_running_time;

Client::Client() {}
Client::Client(string psw, string id) : psw(psw), id(id)
{
    auto start = chrono::high_resolution_clock::now();

    element_init_Zr(this->r, pairing);
    element_random(this->r);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

string Client::getID()
{
    auto start = chrono::high_resolution_clock::now();

    return this->id;


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::blindPassword(element_t &a)
{
    auto start = chrono::high_resolution_clock::now();

    char *psw_char = new char[this->psw.size() + 1];
    strcpy(psw_char, this->psw.c_str());
    // Hash to G1
    element_from_hash(h, psw_char, strlen(psw_char));
    // Blindness
    element_pow_zn(a, h, this->r);


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::pwdGen(element_t &b, string pwd)
{
    auto start = chrono::high_resolution_clock::now();

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
    pwd = sha256Hash(input1).substr(0, secureParam / 4);


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::CredentialGen(string &s_id, string &cred_ks, string &cred_cs, element_t &b)
{
    auto start = chrono::high_resolution_clock::now();

    pwdGen(b, cred_cs);

    Integer s_id_int = randomGeneration(secureParam);
    s_id = Integer_to_string(s_id_int);

    CryptoPP::byte cred_ks_byte[16];
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(cred_ks_byte, sizeof(cred_ks_byte), 0, (CryptoPP::byte *)this->psw.data(), this->psw.size(), (CryptoPP::byte *)s_id.data(), s_id.size(), 10000);
    HexEncoder hex(new StringSink(cred_ks));
    hex.Put(cred_ks_byte, sizeof(cred_ks_byte));
    hex.MessageEnd();
    std::cout << "Derived key: " << cred_ks << std::endl;


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::loginToCS_Give(string &r_id, string &s_id, string &cred_cs, string &id, element_t &b)
{
    auto start = chrono::high_resolution_clock::now();

    pwdGen(b, cred_cs);

    r_id = Integer_to_string(randomGeneration(secureParam));


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::loginToKS_Give(string &t, string &k_1, string &k_2, string &ct, string &tag, string &s_id, string &r_id)
{
    auto start = chrono::high_resolution_clock::now();

    string mk = Integer_to_string(randomGeneration(secureParam));

    CryptoPP::byte t_byte[16];
    KDF(t, this->psw, s_id, t_byte);

    CryptoPP::byte k1_byte[16];
    KDF(k_1, this->psw, r_id, k1_byte);

    CryptoPP::byte k2_byte[16];
    KDF(k_2, this->psw, r_id, k2_byte);

    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(k_1, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));
    AutoSeededRandomPool prng;
    CryptoPP::byte dsk_iv[16];
    prng.GenerateBlock(dsk_iv, 16);

    aes_CBC_Enc(mk, aes_key, dsk_iv, ct);

    // Store the iv for decryption in KeyRetrieval
    string dsk_iv_str;
    StringSource(dsk_iv, 16, true, new HexEncoder(new StringSink(dsk_iv_str)));

    string filename = "../Store/Client_iv.bin";
    
    ofstream outFile(filename, ios::binary);

    if (!outFile.is_open())
    {
        cout << "Error opening file for writing." << endl;
    }

    writeToBin(outFile, dsk_iv_str);

    outFile.close();

    string input = ct + k_2;
    tag = sha256Hash(input).substr(0, secureParam / 4);


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::loginToKS_Take(string &t, string &k_1, string &k_2, string &s_id, string &r_id)
{
    auto start = chrono::high_resolution_clock::now();

    CryptoPP::byte t_byte[16];
    KDF(t, this->psw, s_id, t_byte);

    CryptoPP::byte k1_byte[16];
    KDF(k_1, this->psw, r_id, k1_byte);

    CryptoPP::byte k2_byte[16];
    KDF(k_2, this->psw, r_id, k2_byte);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::recover(string &mk, string &k_1, string &k_2, string &ct, string &tag)
{
    auto start = chrono::high_resolution_clock::now();

    CryptoPP::byte dsk_iv[16];

    string filename = "../Store/Client_iv.bin";

    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
        return;
    }
    
    string dsk_iv_str;
    readFromBin(inFile, dsk_iv_str);
    inFile.close();

    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(k_1, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));
    CryptoPP::StringSource(dsk_iv_str, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(dsk_iv, 16)));
    
    string input = ct + k_2;
    string local_tag = sha256Hash(input).substr(0, secureParam / 4);

    if (tag != local_tag) {
        cout << "The integrity verification fails!" << endl;
        return ;
    }

    aes_CBC_Dec(ct, aes_key, dsk_iv, mk);


    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();

    cout << "The running time of the client: " << client_running_time << endl;
}

void Client::dataEncryption(string &sk, CryptoPP::byte* iv)
{
    string infilename = "../Store/data.txt";
    string outfilename = "../Store/encryption.bin";

    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(sk, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));

    aes_EAX_FileEnc(infilename, aes_key, iv, outfilename);
}

void Client::dataDecryption(string &sk, CryptoPP::byte* iv)
{
    string infilename = "../Store/encryption.bin";
    string outfilename = "../Store/decryption.txt";

    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(sk, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));

    aes_EAX_FileDec(infilename, aes_key, iv, outfilename);
}
