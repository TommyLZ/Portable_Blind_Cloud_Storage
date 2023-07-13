#include <iostream>
#include <cryptopp/integer.h>
#include <pbc/pbc.h>
using namespace std;
using namespace CryptoPP;

class KeyServer {
private:
    element_t secret_key;
    Integer nr;
public:
    element_t public_key;

    KeyServer();

    Integer getnr();

    void hardenPassword(element_t &b, element_t &a);

    void encrypt(element_t& sig1, element_t& sig2);

    void decrypt(element_t& c1, element_t& c0);
};