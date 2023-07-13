#include "PublicParam.h"
#include "KeyServer.h"

#include <iostream>
#include <fstream>
#include <pbc/pbc.h>
using namespace std;

extern const int secureParam;

extern pairing_t pairing;
extern element_t h;
extern double key_running_time;

static bool master_key_generated = false;

KeyServer::KeyServer()
{
    auto start = chrono::high_resolution_clock::now();
    
    string filename = "../Store/msk.bin";
    string msk_str;

    if (!master_key_generated)
    {
        this->msk = randomGeneration(secureParam);
        master_key_generated = true;
        msk_str = Integer_to_string(this->msk);

        ofstream outFile(filename, ios::binary | ios::app);
        if (!outFile.is_open())
        {
            cout << "Error opening file for writing." << endl;
            return;
        }
        writeToBin(outFile, msk_str);
        outFile.close();
    }
    else
    {
        ifstream inFile(filename, ios::binary | ios::app);

        if (!inFile.is_open())
        {
            cout << "Error opening file for writing." << endl;
            return;
        }

        readFromBin(inFile, msk_str);
        this->msk = string_To_Integer(msk_str);
        inFile.close();
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

void KeyServer::hardenPassword(element_t &b, element_t &a, string id)
{
    auto start = chrono::high_resolution_clock::now();
    
    string msk_str = Integer_to_string(this->msk);
    char *msk_id = new char[msk_str.size() + id.size() + 1];
    strcpy(msk_id, msk_str.c_str());
    strcat(msk_id, id.c_str());

    element_t k_id;
    element_init_Zr(k_id, pairing);
    element_from_hash(k_id, msk_id, strlen(msk_id));
    element_pow_zn(b, a, k_id);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

void KeyServer::store(string &id, string &cred_ks)
{
    auto start = chrono::high_resolution_clock::now();

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

    if (!outFile.is_open())
    {
        cout << "Error opening file for writing." << endl;
        return;
    }

    writeToBin(outFile, id);
    writeToBin(outFile, cred_ks);

    outFile.close();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

void KeyServer::authenInGive_KS(string &id, string &t, string &ct, string &tag)
{
    auto start = chrono::high_resolution_clock::now();
    
    string filename = "../Store/Cred_ks.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
        return;
    }

    readFromBin(inFile, id);

    string cred_KS;
    readFromBin(inFile, cred_KS);

    inFile.close();

    if (cred_KS != t)
    {
        cout << "The key server authentication fails!" << endl;
        return ;
    }

    ofstream outFile(filename, ios::binary| ios::app);   
    if (!outFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    writeToBin(outFile, ct);
    writeToBin(outFile, tag);
    
    outFile.close();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
}

void KeyServer::authenInTake_KS(string& ct, string& tag, string &t, string& id) {
    auto start = chrono::high_resolution_clock::now();
    
    string filename = "../Store/Cred_ks.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
        return;
    }

    readFromBin(inFile, id);

    string cred_KS;
    readFromBin(inFile, cred_KS);
    readFromBin(inFile, ct);
    readFromBin(inFile, tag);

    inFile.close();

    if (cred_KS != t)
    {
        cout << "The key server authentication fails!" << endl;
        return ;
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    key_running_time += duration.count();
    
    cout << "The running time of the key server is: " << key_running_time << endl;
}