#include <iostream>
#include <cryptopp/integer.h>
#include <pbc/pbc.h>
using namespace std;
using namespace CryptoPP;

class CloudServer {
private:
    element_t secret_key;
    Integer ns;
public:
    CloudServer();

    void store(string &id, string &cred_cs);

    void authenInEnc(string& id, string& cred_cs);

    void encrypt(Integer nr, element_t& sig0, element_t& sig1, element_t& public_key, string& cred_cs);

    void decrypt(element_t& c0, string& cred_cs, element_t& hr1, element_t& hs1);

    void key_Recover(element_t& mk, element_t& c1, element_t& hr1, element_t& hs1, element_t& public_key);

    void dataEncryption(element_t& mk, CryptoPP::byte *iv);

    void dataDecryption(element_t& mk, CryptoPP::byte *iv);
};
