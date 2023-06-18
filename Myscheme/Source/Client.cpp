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

using namespace CryptoPP;
using namespace std;

Client::Client() {}

Client::Client(char *psw_u, char *ID_u) : psw_u(psw_u), ID_u(ID_u)
{
    element_init_Zr(this->r, pairing);
    element_random(this->r);
}

char *Client::getPassword()
{
    return this->psw_u;
}

char *Client::getID()
{
    return this->ID_u;
}

void Client::blindPassword(element_t &alpha)
{
    char *psw_id_str = new char[strlen(this->psw_u) + strlen(this->ID_u) + 1];
    strcpy(psw_id_str, this->psw_u);
    strcat(psw_id_str, this->ID_u);

    // Hash to G1
    element_from_hash(h, psw_id_str, strlen(psw_id_str));

    // Blindness
    element_pow_zn(alpha, h, this->r);
}

string Client::verifyKS(element_t &alpha, element_t &beta, element_t &public_key)
{
    element_t tmp1, tmp2;

    element_init_GT(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    pairing_apply(tmp1, beta, g, pairing);
    pairing_apply(tmp2, alpha, public_key, pairing);

    if (!element_cmp(tmp1, tmp2))
    {
        cout << "signature verifies" << endl;
    }
    else
    {
        cout << "signature does not verify" << endl;
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

    return pwd_u_hat;
}

void Client::CredentialGen(string &s_u, string &cred_ks, string &cred_cs, element_t &alpha, element_t &beta, element_t &public_key)
{
    string psw_u_hat = verifyKS(alpha, beta, public_key);
    string input1 = psw_u_hat.substr(0, secureParam / 4) + "cloudserver";
    cred_cs = sha256Hash(input1);

    s_u = Integer_to_string(randomGeneration(secureParam));
    string input2 = "keyserver" + psw_u_hat.substr(0, secureParam / 4) + s_u;
    cred_ks = sha256Hash(input2);
}

void Client::loginToCS(string &psw_u_hat, string &EM_CS, const CryptoPP::byte *iv, element_t &alpha, element_t &beta, element_t &public_key)
{
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

    cout << "The client ready to log in the cloud server" << endl;
}

void Client::loginToKS(string &psw_u_hat, string &s_u, string &EM_KS, CryptoPP::byte *iv)
{
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
}

void Client::loginToKS_KeyOutsource(string &EM_KS, string &ctx_sk, string &rho_u, string &gamma_u, CryptoPP::byte *iv, string &s_u, string &psw_u_hat)
{
    loginToKS(psw_u_hat, s_u, EM_KS, iv);

    // Select the symmetric key for cloud storage
    Integer sk = randomGeneration(secureParam);
    string sk_str = Integer_to_string(sk);

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

    ofstream outfile(filename, ios::binary);

    if (!outfile.is_open())
    {
        cout << "Error opening file for writing." << endl;
    }

    int dsk_iv_strLength = dsk_iv_str.length();
    outfile.write(reinterpret_cast<char *>(&dsk_iv_strLength), sizeof(int));
    outfile.write(dsk_iv_str.c_str(), dsk_iv_strLength);
    outfile.close();

    // Genrate the integerity tag
    string integrity_hash_input = ctx_sk + dsk_str;
    rho_u = sha256Hash(integrity_hash_input).substr(0, secureParam / 4);

    cout << "The client ready to log in the key server" << endl;
}

void Client::retrieval(string &sk, string &gamma_u, string &psw_u_hat, string &ctx_sk, string &rho_u)
{
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
    }

    CryptoPP::byte dsk_iv[16];

    string filename = "../Store/Client_iv.bin";

    ifstream infile(filename, ios::binary);

    if (!infile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    int dsk_ivLength;
    infile.read(reinterpret_cast<char *>(&dsk_ivLength), sizeof(int));
    char *dsk_iv_char = new char[dsk_ivLength + 1];
    infile.read(dsk_iv_char, dsk_ivLength);
    dsk_iv_char[dsk_ivLength] = '\0';
    string dsk_iv_str(dsk_iv_char);
    infile.close();

    // Generate the symmetric key
    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(dsk_str, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));
    CryptoPP::StringSource(dsk_iv_str, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(dsk_iv, 16)));

    aes_CBC_Dec(ctx_sk, aes_key, dsk_iv, sk);
}

void Client::dataEncryption(string &sk, CryptoPP::byte* iv)
{
    string infilename = "../Store/data.txt";
    string outfilename = "../Store/encryption.bin";

    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(sk, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));

    cout << "the decryption server: " << endl;
    aes_EAX_FileEnc(infilename, aes_key, iv, outfilename);
}

void Client::dataDecryption(string &sk, CryptoPP::byte* iv)
{
    string infilename = "../Store/encryption.bin";
    string outfilename = "../Store/decryption.txt";

    CryptoPP::byte aes_key[16];
    CryptoPP::StringSource(sk, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(aes_key, 16)));

    cout << "the last danceh" << endl;
    aes_EAX_FileDec(infilename, aes_key, iv, outfilename);
}