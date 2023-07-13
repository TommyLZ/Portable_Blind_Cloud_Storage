#include <iostream>
#include <pbc/pbc.h>
using namespace std;

class Client {
private:
    string psw;
    string id;
    element_t r;
public:
    Client();

    Client(string& psw, string& id);

    void blindPassword(element_t &alpha);

    void CredentialGen(string& cred_cs, element_t& b, element_t& a, element_t& public_key);
};