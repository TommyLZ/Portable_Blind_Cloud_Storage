#pragma once

#include <cryptopp/integer.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

// Secure Parameter
const int secureParam = 128;

// Running time statistic variable
static double client_running_time = 0.0;
static double cloud_running_time = 0.0;
static double key_running_time = 0.0;

// System initialization
void sysInitial();

// Random generation
Integer randomGeneration(const int &secureParam);

// Hash computation
string sha256Hash(string &str);

// Write a string into a .bin file
void writeToBin(ofstream &outFile, string str);

// Read a string into a .bin file
void readFromBin(ifstream &inFile, string &str);

// Transfrom integer to string
string Integer_to_string(const Integer &integer);

// Transfrom element_t to string
string elementToString(element_t& element);

// Save the data to the binary file 
void save_to_file(element_t key, const char *filename);

// Load the data to the binary file
void load_from_file(element_t key, const char *filename);

// Verify the ZKP
void verify(element_t &beta, element_t &alpha, element_t &public_key);

// Save the state of the servers
void save_State(const Integer& nr, const string& filename);

// Load the state of the servers
Integer load_State(const string& filename);

// AES_EAX authentication encryption operation
void aes_EAX_FileEnc(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);

// AES_EAX authentication decryption operation
void aes_EAX_FileDec(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);

// Get the client running time
double getClientTime ();