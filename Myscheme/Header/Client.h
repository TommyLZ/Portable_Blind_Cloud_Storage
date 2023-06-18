#pragma once

#include <pbc/pbc.h>
#include <cryptopp/config.h>

using namespace std;
using namespace CryptoPP;

class Client
{
private:

	char* psw_u;
	char* ID_u;
	element_t r;

public:

	Client();
	Client(char* psw_u, char* ID_u);

	char* getPassword();
	char* getID();

    void blindPassword(element_t& alpha);

    string verifyKS(element_t& alpha, element_t& beta, element_t& public_key);

	void CredentialGen(string& s_u, string& cred_ks, string& cred_cs, element_t& alpha, element_t& beta, element_t& public_key);

	void loginToCS (string& psw_u_hat, string& EM_CS, const CryptoPP::byte *iv, element_t& alpha, element_t& beta, element_t& public_key);

	void loginToKS(string& psw_u_hat, string& s_u, string& EM_KS, CryptoPP::byte* iv);
	void loginToKS_KeyOutsource(string& EM_KS, string& ctx_dsk, string& rho_u, string& gamma_u, CryptoPP::byte *iv, string& s_u, string& psw_u_hat);

	void retrieval(string& sk, string& gamma_u, string& psw_u_hat, string& ctx_dsk, string& rho_u);

	void dataEncryption(string& sk, CryptoPP::byte* iv);
	void dataDecryption(string& sk, CryptoPP::byte* iv);
};