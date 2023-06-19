#pragma once

#include <cryptopp/integer.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

// Secure Parameter
const int secureParam = 128;

// System Initialization
void sysInitial();

// Converts a byte array to a hexadecimal string
string hex_encode(const unsigned char *buffer, int length);

// Hash computation
string sha256Hash(string &str);

// Random Generation
Integer randomGeneration(const int &secureParam);

// Transfrom integer to string
string Integer_to_string(const Integer &integer);

// Transfrom string to integer
Integer string_To_Integer(string &Integer);

// Transfrom Integer to bytes
void integer_To_Bytes(Integer num, CryptoPP::byte *bytes);

// Write a string into a .bin file
void writeToBin(ofstream& outFile, string str);

// Read a string from a .bin file
void readFromBin(ifstream& inFile, string& str);

// AES_CBC encryption operation
void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher);

// AES_CBC decryption operation
void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain);

void authentication(string &ID_u_str, string &cred, string &EM, CryptoPP::byte *iv);

// AES_EAX authentication encryption operation
void aes_EAX_FileEnc(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);

// AES_EAX authentication decryption operation
void aes_EAX_FileDec(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);