#include "Take.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"

#include <iostream>
#include <cryptopp/osrng.h>
using namespace std;

extern pairing_t pairing;

void Take(string& psw, string& id)
{
    cout << "**********************************Take phase**********************************" << endl;
	// User inputs password & ID to the Client
	// Object instantiation
	Client client(psw, id);
	KeyServer keyserver;
	CloudServer cloudserver;

	// Password blindness
	element_t a;
	element_init_G1(a, pairing);
	client.blindPassword(a);
	cout << "The client blinds the password and sends it to the key server!" << endl;

	// Password hardening
	element_t b;
	element_init_G1(b, pairing);
	keyserver.hardenPassword(b, a, id);
	cout << "Password Hardening Finished!" << endl;

    // Log in to the cloud server
    string cred_cs;
    client.pwdGen(b, cred_cs);
	cout << "The client ready to log in the cloud server!" << endl;

    // Cloud server authenticates the client
    string s_id;
    string r_id;
    cloudserver.authenInTake_CS(s_id, r_id, id, cred_cs);
    cout << "You have successfully logged in the cloud server!" << endl;

    string t;
    string k_1;
    string k_2;
    client.loginToKS_Take(t, k_1, k_2, s_id, r_id);
	cout << "The client ready to log in the key server!" << endl;
	
	string ct;
	string tag;
	keyserver.authenInTake_KS(ct, tag, t, id);
    cout << "You have successfully logged in the key server!" << endl;
	
	string mk;
	client.recover(mk, k_1, k_2, ct, tag);
	cout << "The key recovery is finished!" << endl;

	// CryptoPP::byte iv[16 * 16];
	// AutoSeededRandomPool prng;
	// prng.GenerateBlock(iv, 16 * 16);
	
	// client.dataEncryption(mk, iv);
	// cout << "The applicaiton data is encrypted and outsourced successfully!" << endl;
	// client.dataDecryption(mk, iv);
	// cout << "The applicaiton data is recovered successfully!" << endl;
}