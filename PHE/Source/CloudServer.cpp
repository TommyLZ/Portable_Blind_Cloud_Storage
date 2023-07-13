#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <pbc/pbc.h>
using namespace std;
using namespace CryptoPP;

extern pairing_t pairing;
extern double cloud_running_time;

static bool secret_key_generated = false;

CloudServer::CloudServer()
{
    auto start = chrono::high_resolution_clock::now();

    element_init_Zr(this->secret_key, pairing);

    if (!secret_key_generated)
    {
        // Generate the key pair
        element_random(this->secret_key);
        this->ns = randomGeneration(secureParam);

        // Store the key pair
        save_to_file(this->secret_key, "../Store/cs_secret_key.bin");
        save_State(this->ns, "../Store/cs_state.bin");

        // Set a tag to control one-time generation
        secret_key_generated = true;
    }
    else
    {
        load_from_file(this->secret_key, "../Store/cs_secret_key.bin");
        this->ns = load_State("../Store/cs_state.bin");
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::store(string &id, string &cred_cs)
{
    auto start = chrono::high_resolution_clock::now();
    
    string filename = "../Store/Cred_cs.bin";

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
    }

    writeToBin(outFile, id);
    writeToBin(outFile, cred_cs);

    outFile.close();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::authenInEnc(string &id, string &cred_cs)
{
    auto start = chrono::high_resolution_clock::now();
    
    string filename = "../Store/Cred_cs.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    readFromBin(inFile, id);
    string cred_CS;
    readFromBin(inFile, cred_CS);

    inFile.close();

    if (cred_CS != cred_cs)
    {
        cout << "The cloud server authentication fails!" << endl;
        return;
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::encrypt(Integer nr, element_t& c0, element_t& c1, element_t& public_key, string& cred_cs)
{
    auto start = chrono::high_resolution_clock::now();

    string input0_str = Integer_to_string(nr) + "0";
    char* input0 = new char [input0_str.size() + 1];
    strcpy(input0, input0_str.c_str());

    string input1_str = Integer_to_string(nr) + "1";
    char* input1 = new char [input1_str.size() + 1];
    strcpy(input1, input1_str.c_str());

    element_t hr0;
    element_init_G1(hr0, pairing);
    element_t hr1;
    element_init_G1(hr1, pairing);
    element_from_hash(hr0, input0, strlen(input0));
    element_from_hash(hr1, input1, strlen(input1));
    
    // Check the ZKP
    verify(c0, hr0, public_key);
    verify(c1, hr1, public_key);

    // The cloud serve generate the local states input
    string input0_str0 = cred_cs + Integer_to_string(this->ns) + "0";
    char* input00 = new char [input0_str0.size() + 1];
    strcpy(input00, input0_str0.c_str());

    string input1_str1 = cred_cs + Integer_to_string(this->ns) + "1";
    char* input11 = new char [input1_str1.size() + 1];
    strcpy(input11, input1_str1.c_str());
    
    // The cloud serve generate the local states
    element_t hs0;
    element_init_G1(hs0, pairing);
    element_t hs1;
    element_init_G1(hs1, pairing);
    element_from_hash(hs0, input00, strlen(input00));
    element_from_hash(hs1, input11, strlen(input11));
    // element_printf("hs0 in enc: %B\n", hs0);

    element_t tmp1, tmp2, tmp3, tmp4, t0, t1, mk;
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_G1(tmp4, pairing);
    element_init_G1(t0, pairing);
    element_init_G1(t1, pairing);
    element_init_G1(mk, pairing);

    // Randomly select a symmetric key
    element_random(mk);
    // element_printf("the symmetric key generated is %B\n", mk);

    // The first part of the ciphertext
    element_pow_zn(tmp1, hs0, this->secret_key);
    element_mul(t0, c0, tmp1);
    // element_printf("t0 beore write: %B\n", t0);

    // The seconde part of the ciphertext
    element_pow_zn(tmp2, hs1, this->secret_key);
    element_pow_zn(tmp3, mk, this->secret_key);
    // element_printf("mk^y is %B\n", tmp3);
    element_mul(tmp4, tmp2, tmp3);
    // element_printf("t1/c1 is %B\n", tmp4);
    element_mul(t1, c1, tmp4);
    // element_printf("t1 is %B\n", t1);

    // element_printf("t0 before save: %B\n", t0);
    save_to_file(t0, "../Store/cipher0.bin");
    save_to_file(t1, "../Store/cipher1.bin");

    delete[] input0;
    delete[] input1;
    delete[] input00;
    delete[] input11;

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::decrypt(element_t& c0, string& cred_cs, element_t& hr1, element_t& hs1) {
    auto start = chrono::high_resolution_clock::now();

    Integer nr = load_State("../Store/ks_state.bin");

    string input0_str = Integer_to_string(nr) + "0";
    char* input0 = new char [input0_str.size() + 1];
    strcpy(input0, input0_str.c_str());

    string input1_str = Integer_to_string(nr) + "1";
    char* input1 = new char [input1_str.size() + 1];
    strcpy(input1, input1_str.c_str());

    element_t hr0;
    element_init_G1(hr0, pairing);
    element_from_hash(hr0, input0, strlen(input0));

    element_from_hash(hr1, input1, strlen(input1));

    string input0_str0 = cred_cs + Integer_to_string(this->ns) + "0";
    char* input00 = new char [input0_str0.size() + 1];
    strcpy(input00, input0_str0.c_str());

    string input1_str1 = cred_cs + Integer_to_string(this->ns) + "1";
    char* input11 = new char [input1_str1.size() + 1];
    strcpy(input11, input1_str1.c_str());
    
    element_t hs0;
    element_init_G1(hs0, pairing);

    element_from_hash(hs0, input00, strlen(input00));
    element_from_hash(hs1, input11, strlen(input11));

    // Initialize some temporary variable
    element_t invert, tmp1, t0, t1, mk;
    element_init_Zr(invert, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(t0, pairing);

    // Load the first part of the cipher and compute the c0 for the key server
    load_from_file(t0, "../Store/cipher0.bin");
    element_pow_zn(tmp1, hs0, this->secret_key);
    element_div(c0, t0, tmp1);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::key_Recover(element_t& mk, element_t& c1, element_t& hr1, element_t& hs1, element_t& public_key) {
    auto start = chrono::high_resolution_clock::now();

    verify(c1, hr1, public_key);

    //Recover the symmetric key
    element_t tmp1, tmp2, tmp3, inverse, t1;
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_G1(t1, pairing);
    element_init_Zr(inverse, pairing);

    load_from_file(t1, "../Store/cipher1.bin");
    // element_printf("t1 is %B\n", t1);
    element_div(tmp1, t1, c1);
    // element_printf("t1/c1 is %B\n",tmp1);
    element_pow_zn(tmp2, hs1, this->secret_key);
    element_div(tmp3, tmp1, tmp2);
    // element_printf("mk^y is %B\n",tmp3);   

    element_invert(inverse, this->secret_key);
    // element_printf("inverse is %B\n", inverse);
    element_pow_zn(mk, tmp3, inverse);
    // element_printf("the recovered symmetric key is %B\n", mk);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();

    cout << "The cloud server running time: " << cloud_running_time << endl;
}

void CloudServer::dataEncryption (element_t& mk, CryptoPP::byte *iv) {
    string infilename = "../Store/data.txt";
    string outfilename = "../Store/encryption.bin";

    string mk_str = elementToString(mk);

    CryptoPP::byte aes_key[16];
    StringSource(mk_str, true, new HexDecoder(new ArraySink(aes_key, 16)));

    aes_EAX_FileEnc(infilename, aes_key, iv, outfilename);
}

void CloudServer::dataDecryption (element_t& mk, CryptoPP::byte *iv) {
    string infilename = "../Store/encryption.bin";
    string outfilename = "../Store/decryption.txt";

    string mk_str = elementToString(mk);

    CryptoPP::byte aes_key[16];
    StringSource(mk_str, true, new HexDecoder(new ArraySink(aes_key, 16)));

    aes_EAX_FileDec(infilename, aes_key, iv, outfilename);
}