#include <iostream>
#include <cryptopp/integer.h>
#include <pbc/pbc.h>
using namespace std;
using namespace CryptoPP;

class Client {
private:
    string psw;
    string id;
    element_t r;

public:
    Client();
    Client(string psw, string id);

    string getID();

    void blindPassword(element_t& alpha);

    void pwdGen(element_t& b, string pwd);
    void CredentialGen(string& s_id, string& cred_ks, string& cred_cs, element_t& b);

    void loginToCS_Give(string& r_id, string& s_id, string& cred_cs, string& id, element_t& b);

    void loginToKS_Give(string& t, string& k_1, string& k_2, string& ct, string& tag, string& s_id, string& r_id);

    void loginToKS_Take(string& t, string& k_1, string& k_2, string& s_id, string& r_id);

    void recover(string& mk, string& k_1, string& k_2, string& ct, string& tag);

	void dataEncryption(string& sk, CryptoPP::byte* iv);
	void dataDecryption(string& sk, CryptoPP::byte* iv);
};