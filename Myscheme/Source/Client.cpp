#include "Client.h"
#include "PublicParam.h"

#include <iostream>
#include <cstring>
#include <ctime>
#include <sstream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/config.h>
#include <pbc/pbc.h>

extern const int secureParam;
extern pairing_t pairing;
extern element_t g, h;
extern double client_running_time;

using namespace CryptoPP;
using namespace std;

Client::Client() {}

Client::Client(char *psw_u, char *ID_u) : psw_u(psw_u), ID_u(ID_u)
{
    auto start = chrono::high_resolution_clock::now();
    
    element_init_Zr(this->r, pairing);
    element_random(this->r);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

char *Client::getPassword()
{
    auto start = chrono::high_resolution_clock::now();
    
    return this->psw_u;

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

char *Client::getID()
{
    auto start = chrono::high_resolution_clock::now();

    return this->ID_u;

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::blindPassword(element_t &alpha)
{
    auto start = chrono::high_resolution_clock::now();
    
    char *psw_id_str = new char[strlen(this->psw_u) + strlen(this->ID_u) + 1];
    strcpy(psw_id_str, this->psw_u);
    strcat(psw_id_str, this->ID_u);

    // Hash to G1
    element_from_hash(h, psw_id_str, strlen(psw_id_str));

    // Blindness
    element_pow_zn(alpha, h, this->r);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

string Client::verifyKS(element_t &alpha, element_t &beta, element_t &public_key)
{
    auto start = chrono::high_resolution_clock::now();
    
    element_t tmp1, tmp2;

    element_init_GT(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    pairing_apply(tmp1, beta, g, pairing);
    pairing_apply(tmp2, alpha, public_key, pairing);

    if (!element_cmp(tmp1, tmp2))
    {
        cout << "The key server verifies!" << endl;
    }
    else
    {
        cout << "The key server not verify!" << endl;
        return "Error!";
    }

    // Deblindness
    element_t r_inverse;
    element_init_Zr(r_inverse, pairing);
    element_invert(r_inverse, this->r);
    element_pow_zn(h, beta, r_inverse);

    // Transform from element_t to string
    string salt;
    stringstream ss;
    int h_len = element_length_in_bytes(h);
    unsigned char *h_bytes = new unsigned char[h_len];
    element_to_bytes(h_bytes, h);
    for (int i = 0; i < h_len; i++)
    {
        ss << std::hex << (int)h_bytes[i];
    }
    salt = ss.str();

    // Generate the pwd_u_hat
    string str1 = this->psw_u + salt;
    string pwd_u_hat = sha256Hash(str1);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();

    return pwd_u_hat;
}

void Client::CredentialGen(string &s_u, string &cred_ks, string &cred_cs, element_t &alpha, element_t &beta, element_t &public_key)
{
    auto start = chrono::high_resolution_clock::now();
    
    string psw_u_hat = verifyKS(alpha, beta, public_key);
    string input1 = psw_u_hat.substr(0, secureParam / 4) + "cloudserver";
    cred_cs = sha256Hash(input1);

    // Generate a random
    s_u = Integer_to_string(randomGeneration(secureParam));
    string input2 = "keyserver" + psw_u_hat.substr(0, secureParam / 4) + s_u;
    cred_ks = sha256Hash(input2);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::loginToCS(string &psw_u_hat, string &EM_CS, const CryptoPP::byte *iv, element_t &alpha, element_t &beta, element_t &public_key)
{
    auto start = chrono::high_resolution_clock::now();
    
    psw_u_hat = verifyKS(alpha, beta, public_key);
    string hash_input = psw_u_hat.substr(0, secureParam / 4) + "cloudserver";
    string omega_cs = sha256Hash(hash_input).substr(0, secureParam / 4);

    time_t current_time = time(nullptr);
    int timestamp = static_cast<int>(current_time);
    string timestamp_str = to_string(timestamp);

    // Generate the symmetric key
    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(omega_cs, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));

    string separator = ":";
    string plain = this->ID_u + separator + timestamp_str;
    aes_CBC_Enc(plain, aes_key, iv, EM_CS);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::loginToKS(string &psw_u_hat, string &s_u, string &EM_KS, CryptoPP::byte *iv)
{
    auto start = chrono::high_resolution_clock::now();
    
    string hash_input = "keyserver" + psw_u_hat.substr(0, secureParam / 4) + s_u;
    string omega_ks = sha256Hash(hash_input).substr(0, secureParam / 4);

    time_t current_time = time(nullptr);
    int timestamp = static_cast<int>(current_time);
    string timestamp_str = to_string(timestamp);

    // Generate the symmetric key
    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(omega_ks, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));

    string separator = ":";
    string plain = this->ID_u + separator + timestamp_str;
    aes_CBC_Enc(plain, aes_key, iv, EM_KS);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::loginToKS_KeyOutsource(string &EM_KS, string &ctx_sk, string &rho_u, string &gamma_u, CryptoPP::byte *iv, string &s_u, string &psw_u_hat)
{
    auto start = chrono::high_resolution_clock::now();
    
    loginToKS(psw_u_hat, s_u, EM_KS, iv);

    // Select the symmetric key for cloud storage
    Integer sk = randomGeneration(secureParam);
    // cout << "The random selected key is: " << hex << sk << endl;
    string sk_str = Integer_to_string(sk);
    // cout << "The random selected key is: " << sk_str << endl;

    // Derive the second key to encrypt sk
    Integer gamma_u_int = randomGeneration(secureParam);
    gamma_u = Integer_to_string(gamma_u_int);
    string derive_input = gamma_u + psw_u_hat.substr(0, secureParam / 4);
    string dsk_str = sha256Hash(derive_input).substr(0, secureParam / 4);

    // Generate the symmetric key and encrypt
    CryptoPP::byte dsk_aes_key[16];
    CryptoPP::StringSource(dsk_str, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(dsk_aes_key, 16)));
    AutoSeededRandomPool dsk_prng;
    CryptoPP::byte dsk_iv[16];
    dsk_prng.GenerateBlock(dsk_iv, 16);

    aes_CBC_Enc(sk_str, dsk_aes_key, dsk_iv, ctx_sk);

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

    // Genrate the integerity tag
    string integrity_hash_input = ctx_sk + dsk_str;
    rho_u = sha256Hash(integrity_hash_input).substr(0, secureParam / 4);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void Client::retrieval(string &sk, string &gamma_u, string &psw_u_hat, string &ctx_sk, string &rho_u)
{
    auto start = chrono::high_resolution_clock::now();
    
    string derive_input = gamma_u + psw_u_hat.substr(0, secureParam / 4);
    string dsk_str = sha256Hash(derive_input).substr(0, secureParam / 4);

    string integrity_hash_input = ctx_sk + dsk_str;
    string rho_u_check = sha256Hash(integrity_hash_input).substr(0, secureParam / 4);

    if (rho_u_check == rho_u)
    {
        cout << "The integrity verifies!" << endl;
    }
    else
    {
        cout << "The integrity not verify" << endl;
        return;
    }

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

    // Generate the symmetric key
    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(dsk_str, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));
    CryptoPP::StringSource(dsk_iv_str, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(dsk_iv, 16)));

    aes_CBC_Dec(ctx_sk, aes_key, dsk_iv, sk);

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