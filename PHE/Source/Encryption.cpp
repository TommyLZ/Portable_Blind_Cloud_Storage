#include "Encryption.h"

#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"

extern pairing_t pairing;

void Encryption(string &psw, string &id){
    cout << "***********************************Encryption Phase*********************************" << endl;

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
	keyserver.hardenPassword(b, a);	
	cout << "Password Hardening Finished!" << endl;

    // Log in to the cloud server
	string cred_cs;
    client.CredentialGen(cred_cs, b, a, keyserver.public_key);
	cout << "The client ready to log in the cloud server!" << endl;

	// Cloud server authenticates the client
    cloudserver.authenInEnc(id, cred_cs);
    cout << "You have successfully logged in the cloud server!" << endl;

    // Encrypt the symmetric key
    element_t hr0;
    element_init_G1(hr0, pairing);
    element_t hr1;
    element_init_G1(hr1, pairing);
    element_t c0;
    element_init_G1(c0, pairing);
    element_t c1;
    element_init_G1(c1, pairing);
    keyserver.encrypt(c0, c1);
    cloudserver.encrypt(keyserver.getnr(), c0, c1, keyserver.public_key, cred_cs);
	cout << "The Encryption is finished!" << endl;
}