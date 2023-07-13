#include "CloudServer.h"
#include "PublicParam.h"
#include <fstream>

using namespace std;

extern double cloud_running_time;

CloudServer::CloudServer() {}

void CloudServer::store(string &id, string &cred_cs, string &s_id)
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
    writeToBin(outFile, s_id);

    outFile.close();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}

void CloudServer::authenInGive_CS(string& s_id, string& r_id, string& id, string& cred_cs)
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
    readFromBin(inFile, s_id);

    inFile.close();

    if (cred_CS != cred_cs) {
        cout << "The cloud server authentication fails!" << endl;
        return ;
    }

    ofstream outFile(filename, ios::binary| ios::app);   
    if (!outFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    writeToBin(outFile, r_id);
    
    outFile.close();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();
}


void CloudServer::authenInTake_CS(string& s_id, string& r_id, string& id, string& cred_cs) {
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
    readFromBin(inFile, s_id);
    readFromBin(inFile, r_id);

    if (cred_CS != cred_cs) {
        cout << "The cloud server authentication fails!" << endl;
        return ;
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    client_running_time += duration.count();

    cout << "The running time of the cloud server: " << client_running_time << endl;
}