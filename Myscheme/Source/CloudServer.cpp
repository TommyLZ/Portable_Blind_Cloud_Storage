
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
    // string filename = "../Store/Cred_cs.txt";
    // // Check if the file exists
    // std::ifstream fileCheck(filename);
    // bool fileExists = fileCheck.good();
    // fileCheck.close();

    // if (fileExists) {
    //     // If the file exists, clear the file
    //     std::ofstream clearFile(filename, std::ios::trunc);
    //     clearFile.close();
    // }

    // ofstream out(filename, ios::app);

    // if (out.is_open())
    // {
    //     out << "user_identity:" << ID_u
    //         << "    credential:" << cred_cs.substr(0, secureParam / 4)
    //         << "    s_u:" << s_u;
    // }

    // out.close();

    // cout << "You have successfully registered with the cloud server!" << endl;

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
    int ID_uLength = ID_u_str.length();
    outFile.write(reinterpret_cast<char *>(&ID_uLength), sizeof(int));
    outFile.write(ID_u_str.c_str(), ID_uLength);

    int credLength = cred_cs.substr(0, secureParam/4).length();
    outFile.write(reinterpret_cast<char *>(&credLength), sizeof(int));
    outFile.write(cred_cs.substr(0, secureParam/4).c_str(), credLength);

    int s_uLength = s_u.length();
    outFile.write(reinterpret_cast<char *>(&s_uLength), sizeof(int));
    outFile.write(s_u.c_str(), s_uLength);

    outFile.close();
    cout << "You have successfully registered with the cloud server!" << endl;
}

void CloudServer::authenInGen_CS(string &s_u, char *ID_u, string &EM_CS, CryptoPP::byte (&iv)[16])
{
    // string filename = "../Store/Cred_cs.txt";
    // ifstream in(filename);
    // string ID_u_str;
    // string cred_CS;

    // in >> ID_u_str;
    // in >> cred_CS;
    // in >> s_u;

    string filename = "../Store/Cred_cs.bin";
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
    char *cred_cs_char = new char[credLength + 1];
    inFile.read(cred_cs_char, credLength);
    cred_cs_char[credLength] = '\0';
    string cred_CS(cred_cs_char);

    int s_uLength;
    inFile.read(reinterpret_cast<char *>(&s_uLength), sizeof(int));
    char *s_u_char = new char[s_uLength + 1];
    inFile.read(s_u_char, s_uLength);
    s_u_char[s_uLength] = '\0';
    s_u= s_u_char;

    inFile.close();

    // ID_u_str = ID_u_str.substr(ID_u_str.find(':') + 1, ID_u_str.size());
    // cred_CS = cred_CS.substr(cred_CS.find(':') + 1, cred_CS.size());
    
    authentication(ID_u_str, cred_CS, EM_CS, iv);

    // s_u = s_u.substr(s_u.find(':') + 1, s_u.size());
    // cout << "s_u: " << s_u << endl;
    // cout << "*****************" << endl;
}

void CloudServer::authenInRetrieve_CS(string &s_u, string &gamma_u, char *ID_u, string &EM, CryptoPP::byte *iv)
{
    // string filename = "../Store/Cred_cs.txt";
    // ifstream in(filename, ios::app);
    // string ID_u_str;
    // string cred_CS;

    // in >> ID_u_str;
    // in >> cred_CS;
    // in >> s_u;
    // in >> gamma_u;

    string filename = "../Store/Cred_cs.bin";
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
    char *cred_cs_char = new char[credLength + 1];
    inFile.read(cred_cs_char, credLength);
    cred_cs_char[credLength] = '\0';
    string cred_CS(cred_cs_char);

    int s_uLength;
    inFile.read(reinterpret_cast<char *>(&s_uLength), sizeof(int));
    char *s_u_char = new char[s_uLength + 1];
    inFile.read(s_u_char, s_uLength);
    s_u_char[s_uLength] = '\0';
    s_u = s_u_char;

    int gamma_uLength;
    inFile.read(reinterpret_cast<char *>(&gamma_uLength), sizeof(int));
    char *gamma_u_char = new char[gamma_uLength + 1];
    inFile.read(gamma_u_char, gamma_uLength);
    gamma_u_char[gamma_uLength] = '\0';
    gamma_u = gamma_u_char;

    inFile.close();

    // ID_u_str = ID_u_str.substr(ID_u_str.find(':') + 1, ID_u_str.size());
    // cred_CS = cred_CS.substr(cred_CS.find(':') + 1, cred_CS.size());

    authentication(ID_u_str, cred_CS, EM, iv);

    // s_u = s_u.substr(s_u.find(':') + 1, s_u.size());
    // gamma_u = gamma_u.substr(gamma_u.find(':') + 1, gamma_u.size());
}

void CloudServer::randomStore(string &gamma_u)
{
    string filename = "../Store/Cred_cs.bin";

    ofstream outFile(filename, ios::binary | ios::app);

    if (!outFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    int gamma_uLength = gamma_u.length();
    outFile.write(reinterpret_cast<char *>(&gamma_uLength), sizeof(int));
    outFile.write(gamma_u.c_str(), gamma_uLength);

    cout << "gamma_u: " << gamma_u << endl; 
}