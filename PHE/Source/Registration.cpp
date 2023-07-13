#include "Registration.h"
// #include "Client.h"
// #include "KeyServer.h"
// #include "CloudServer.h"

#include <iostream>
#include <pbc/pbc.h>
using namespace std;

extern pairing_t pairing;

void Registration(string &psw, string &id)
{
    cout << "***********************************Registration Phase*********************************" << endl;

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

	// Credential generation for cloud server
	string cred_cs;
	client.CredentialGen(cred_cs, b, a, keyserver.public_key);
	// Register with cloud server
	cout << "The client ready to register with the cloud server!" << endl;

	cloudserver.store(id, cred_cs);
    cout << "You have successfully registered with the cloud server!" << endl;
}