
#include "PublicParam.h"
#include "Registration.h"
#include "KeyGen.h"
#include "KeyRetrieve.h"

#include <iostream>
#include <chrono>
using namespace std;

int main()
{
    double totalTime1 = 0.0;
    double totalTime2 = 0.0;
    double totalTime3 = 0.0;

    int numIterations = 100;

    char psw_u[] = "f4520tommy";
    char id_u[] = "wolverine";

    sysInitial();

    for (int i=0; i < numIterations; ++i) {
        auto start1 = chrono::high_resolution_clock::now();
        Registration(psw_u, id_u);
        auto end1 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration1 = end1 - start1;
        totalTime1 += duration1.count();

        auto start2 = chrono::high_resolution_clock::now();        
        KeyGen(psw_u, id_u);
        auto end2 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration2 = end2 - start2;
        totalTime2 += duration2.count();

        auto start3 = chrono::high_resolution_clock::now();        
        KeyRetrieve(psw_u, id_u);    
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