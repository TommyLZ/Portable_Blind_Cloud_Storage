#include <iostream>
#include <cryptopp/integer.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

class KeyServer {
private:
Integer msk;

public:
    KeyServer();
    
    void hardenPassword (element_t& b, element_t& a, string id);

    void store(string& id, string& creds_ks);

    void authenInGive_KS(string &id, string &t, string &ct, string &tag);

    void authenInTake_KS(string& ct, string& tag, string &t, string& id);
};