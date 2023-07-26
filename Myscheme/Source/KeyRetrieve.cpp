#include "KeyRetrieve.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
#include <chrono>
#include <cryptopp/osrng.h>
#include <pbc/pbc.h>

extern pairing_t pairing;

using namespace std;
using namespace CryptoPP;

void KeyRetrieve(char *psw_u, char *ID_u)
{
	cout << "**********************************KeyRetrieval Phase**********************************" << endl;
	// User inputs password & ID to the Client
	// Object instantiation
	Client client(psw_u, ID_u);
	KeyServer keyserver;
	CloudServer cloudserver;

	// Password blindness
	element_t alpha;
	element_init_G1(alpha, pairing);
	client.blindPassword(alpha);

	// Password hardening
	element_t beta;
	element_init_G1(beta, pairing);
	keyserver.hardenPassword(beta, alpha, ID_u);
	cout << "Password Hardening Finished!" << endl;

	// Log in to the cloud server
	string psw_u_hat;
	string EM_CS;
	AutoSeededRandomPool prng_CS;
	CryptoPP::byte iv_CS[16];
	prng_CS.GenerateBlock(iv_CS, 16);
	client.loginToCS(psw_u_hat, EM_CS, iv_CS, alpha, beta, keyserver.public_key);
	cout << "The client ready to log in the cloud server!" << endl;

	// Cloud server authenticates the client
	string s_u;
	string gamma_u;
	cloudserver.authenInRetrieve_CS(s_u, gamma_u, client.getID(), EM_CS, iv_CS);
    cout << "You have successfully logged in the cloud server!" << endl;

	// Log in to the cloud server
	string EM_KS;
	AutoSeededRandomPool prng_KS;
	CryptoPP::byte iv_KS[16];
	prng_KS.GenerateBlock(iv_KS, 16);
	client.loginToKS(psw_u_hat, s_u, EM_KS, iv_KS);
	cout << "The client ready to log in the key server!" << endl;

	// Key Server authenticates the client
	string ctx_dsk;
	string rho_u;
	keyserver.authenInRetrieve_KS(ctx_dsk, rho_u, EM_KS, iv_KS);
    cout << "You have successfully logged in the key server!" << endl;

	// Client Retrieval the key
	string sk;
	client.retrieval(sk, gamma_u, psw_u_hat, ctx_dsk, rho_u);
	cout << "The key retrieval is finished!" << endl;

	// CryptoPP::byte iv[16 * 16];
	// AutoSeededRandomPool prng;
	// prng.GenerateBlock(iv, 16 * 16);
	
	// client.dataEncryption(sk, iv);
	// cout << "The applicaiton data is encrypted and outsourced successfully!" << endl;
	// client.dataDecryption(sk, iv);
	// cout << "The applicaiton data is recovered successfully!" << endl;
}