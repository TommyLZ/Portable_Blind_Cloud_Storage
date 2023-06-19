#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
#include <fstream>
#include <cryptopp/config.h>
using namespace std;
using namespace std;

CloudServer::CloudServer() {}

void CloudServer::store(char *ID_u, string &cred_cs, string &s_u)
{
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

    string ID_u_str = ID_u;
    writeToBin(outFile, ID_u_str);
    writeToBin(outFile, cred_cs.substr(0, secureParam / 4));
    writeToBin(outFile, s_u);

    outFile.close();
}

void CloudServer::authenInGen_CS(string &s_u, char *ID_u, string &EM_CS, CryptoPP::byte (&iv)[16])
{
    string filename = "../Store/Cred_cs.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    string ID_u_str;
    readFromBin(inFile, ID_u_str);
    string cred_CS;
    readFromBin(inFile, cred_CS);
    readFromBin(inFile, s_u);

    inFile.close();

    authentication(ID_u_str, cred_CS, EM_CS, iv);
}

void CloudServer::authenInRetrieve_CS(string &s_u, string &gamma_u, char *ID_u, string &EM, CryptoPP::byte *iv)
{
    string filename = "../Store/Cred_cs.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }
    
    string ID_u_str;
    readFromBin(inFile, ID_u_str);
    string cred_CS;
    readFromBin(inFile, cred_CS);
    readFromBin(inFile, s_u);
    readFromBin(inFile, gamma_u);

    inFile.close();

    authentication(ID_u_str, cred_CS, EM, iv);
}

void CloudServer::randomStore(string &gamma_u)
{
    string filename = "../Store/Cred_cs.bin";

    ofstream outFile(filename, ios::binary | ios::app);

    if (!outFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    writeToBin(outFile, gamma_u);
}