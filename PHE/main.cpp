#include "PublicParam.h"
#include "Registration.h"
#include "Encryption.h"
#include "Decryption.h"

#include <iostream>
using namespace std;


int main() {
    double totalTime1 = 0.0;
    double totalTime2 = 0.0;
    double totalTime3 = 0.0;

    string psw = "f4520tommy";;
    string id = "wolverine";

    sysInitial();

    int numIterations = 100;
    for (int i=0; i < numIterations; ++i) {

        auto start1 = chrono::high_resolution_clock::now();
        Registration(psw, id);        
        auto end1 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration1 = end1 - start1;
        totalTime1 += duration1.count();

        auto start2 = chrono::high_resolution_clock::now();     
        Encryption(psw, id);
        auto end2 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration2 = end2 - start2;
        totalTime2 += duration2.count();

        auto start3 = chrono::high_resolution_clock::now(); 
        Decryption(psw, id);
        auto end3 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration3 = end3 - start3;
        totalTime3 += duration3.count();  
    }

    double averageDuration1 = totalTime1 / numIterations;
    double averageDuration2 = totalTime2 / numIterations;
    double averageDuration3 = totalTime3 / numIterations;

    cout << "The average running time of Registration is: " << averageDuration1 << " seconds" << endl;
    cout << "The average running time of Key Generation is: " << averageDuration2 << " seconds" << endl;
    cout << "The average running time of Key Retrieval is: " << averageDuration3 << " seconds" << endl;
}