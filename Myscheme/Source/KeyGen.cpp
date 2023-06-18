
#include "KeyGen.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
#include <pbc/pbc.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/config.h>

using namespace std;
using namespace CryptoPP;

extern pairing_t pairing;

void KeyGen(char *psw_u, char *ID_u) {
	cout << "***************************KeyGeneration Phase***************************" << endl;

	// User inputs password & ID to the Client
	// Object instantiation
	Client client(psw_u, ID_u);
	KeyServer keyserver;
	CloudServer cloudserver;

	cout << "Before blindness" << endl;
	// Password blindness
	element_t alpha;
	element_init_G1(alpha, pairing);
	client.blindPassword(alpha);

	// Password hardening
	element_t beta;
	element_init_G1(beta, pairing);
	keyserver.hardenPassword(beta, alpha);
	cout << "Password Hardening Finished!" << endl;

    // Log in to the cloud server
	string psw_u_hat;
	string EM_CS;
	AutoSeededRandomPool prng_CS;
    CryptoPP::byte iv_CS[16];
	prng_CS.GenerateBlock(iv_CS, 16);
    client.loginToCS(psw_u_hat, EM_CS, iv_CS, alpha, beta, keyserver.public_key);

    // Cloud server authenticates the client
    string s_u;
    cloudserver.authenInGen_CS(s_u, client.getID(), EM_CS, iv_CS);

	// Log in the key server
	string EM_KS;
	string ctx_dsk;
	string rho_u;
	string gamma_u;
	AutoSeededRandomPool prng_KS;
    CryptoPP::byte iv_KS[16];
	prng_KS.GenerateBlock(iv_KS, 16);
    client.loginToKS_KeyOutsource(EM_KS, ctx_dsk, rho_u, gamma_u, iv_KS, s_u, psw_u_hat);

    // Key server authenticates the client
	keyserver.authenInGen_KS(EM_KS, ctx_dsk, rho_u, iv_KS);

	// Cloud server storage the random
	cloudserver.randomStore(gamma_u);

	cout << "The Key generation is finished!" << endl;
}