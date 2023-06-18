
#include "PublicParam.h"
#include "Registration.h"
#include "KeyGen.h"
#include "KeyRetrieve.h"

#include <iostream>
using namespace std;

int main()
{
    char psw_u[] = "f4520tommy";
    char id_u[] = "wolverine";

    sysInitial();

    Registration(psw_u, id_u);

    KeyGen(psw_u, id_u);

    KeyRetrieve(psw_u, id_u);
}