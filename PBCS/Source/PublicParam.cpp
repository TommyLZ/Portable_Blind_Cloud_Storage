#include "PublicParam.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/eax.h>
#include <cryptopp/files.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

pairing_t pairing;
element_t g, h;

// System Initialization
void sysInitial()
{
    cout << "*********************************System Initialization********************************" << endl;
    // Set pbc param
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count)
        pbc_die("input error");

    // Initialize pairing
    pairing_init_set_buf(pairing, param, count);

    // Declare and initialize variables
    element_init_G1(h, pairing);
    element_init_G2(g, pairing);
    
    // Generate the variables
    element_random(g);

    cout << "System initialization finished!" << endl;
}


// Random Generation
Integer randomGeneration(const int &secureParam)
{
    AutoSeededRandomPool prng;
    SecByteBlock randomBlock(secureParam / 8);
    prng.GenerateBlock(randomBlock, randomBlock.size());

    Integer randomInt(randomBlock, randomBlock.size());

    if (randomInt.BitCount() < 128) {
        randomInt <<= (128 - randomInt.BitCount());
    }

    return randomInt;
}

string Integer_to_string(const Integer &integer)
{
    string str;
    stringstream ss;

    ss << hex << integer;
    ss >> str;
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    str = str.substr(0, str.size() - 1);

    return str;
}

// Hash computation
string sha256Hash(string &str)
{
    string value; // To store the hash string
    SHA256 sha256;

    StringSource ss(
        str,
        true,
        new HashFilter(sha256, new HexEncoder(new CryptoPP::StringSink(value))));
    return value;
}

void writeToBin(ofstream& outFile, string str) {
    int strLength = str.length();
    outFile.write(reinterpret_cast<char *>(&strLength), sizeof(int));
    outFile.write(str.c_str(), strLength);
}

void readFromBin(ifstream& inFile, string& str) {
    int strLength;
    inFile.read(reinterpret_cast<char *>(&strLength), sizeof(int));
    char *str_char = new char[strLength + 1];
    inFile.read(str_char, strLength);
    str_char[strLength] = '\0';
    str = str_char;
}

Integer string_To_Integer(string &str)
{
    char *a = new char[200];
    int i = 0;

    for (; i < str.size(); ++i)
    {
        a[i] = str[i];
    }

    a[i++] = 'h';
    a[i] = '\0';

    Integer H(a);

    return H;
}

void KDF(string& key, string& psw, string& salt, CryptoPP::byte* derivedKey) {
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf; 
    pbkdf.DeriveKey(derivedKey, 16, 0, (CryptoPP::byte*)psw.data(), psw.size(), (CryptoPP::byte*)salt.data(), salt.size(), 10000);
    HexEncoder hex(new StringSink(key));
    hex.Put(derivedKey, 16);
    hex.MessageEnd();
}

void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher)
{

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, 16, iv);
    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new Base64Encoder(
                                                    new StringSink(cipher),
                                                    false // do not append a newline
                                                    )));

    // // Pretty print cipher
    // std::string encoded;
    // HexEncoder encoder(new StringSink(encoded));
    // encoder.Put((const CryptoPP::byte *)cipher.data(), cipher.size());
    // encoder.MessageEnd();

    // cout << "plaintext: " << plain << endl;
    // cout << "cipher text: " << encoded << endl;

    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;
}

void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain)
{
    // // Pretty print cipher
    // std::string encoded;
    // HexEncoder encoder(new StringSink(encoded));
    // encoder.Put((const CryptoPP::byte *)cipher.data(), cipher.size());
    // encoder.MessageEnd();
    // std::cout << "cipher text: " << encoded << std::endl;

    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(cipher, true,
                 new Base64Decoder(
                     new StreamTransformationFilter(decryption,
                                                    new StringSink(plain))));
}

void aes_EAX_FileEnc(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename)
{
    ifstream input(infilename);
    if (!input.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    ofstream output(outfilename, ios::binary);
    if (!output)
    {
        cout << "Error opening file for writing." << endl;
    }

    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, 16, iv, 16 * 16);

    const size_t bufferSize = 8192;

    CryptoPP::byte buffer[bufferSize];

    while (input.good())
    {
        input.read(reinterpret_cast<char*>(buffer), bufferSize);
        size_t bytesRead = input.gcount();

        AuthenticatedEncryptionFilter ef(enc,
            new FileSink(output));

        ef.Put(buffer, bytesRead);
        ef.MessageEnd();

        output.flush();
    }

    // string encoded;
    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16*16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;

    input.close();
    output.close();
}

void aes_EAX_FileDec(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename)
{
    ifstream input(infilename, ios::binary);
    if (!input.is_open())
    {
        cout << "Error opening file for reading." << endl;
        return;
    }

    ofstream output(outfilename);
    if (!output.is_open())
    {
        cout << "Error opening file for writing." << endl;
        return ;
    }

    // string encoded;
    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16*16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;

    EAX<AES>::Decryption dec;
    dec.SetKeyWithIV(key, 16, iv, 16 * 16);

    const size_t bufferSize = 8192;

    CryptoPP::byte buffer[bufferSize];

    while (input.good())
    {
        input.read(reinterpret_cast<char*>(buffer), bufferSize);
        size_t bytesRead = input.gcount();

        AuthenticatedDecryptionFilter df(dec,
            new FileSink(output));

        df.Put(buffer, bytesRead);
        df.MessageEnd();

        output.flush();
    }

    input.close();
    output.close();
}
