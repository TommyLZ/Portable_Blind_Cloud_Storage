
#include "Registration.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
#include <pbc/pbc.h>

extern pairing_t pairing;
using namespace std;

void Registration(char *psw_u, char *ID_u)
{
	cout << "***********************************Registration Phase*********************************" << endl;

	// User inputs password & ID to the Client
	// Object instantiation
	Client client(psw_u, ID_u);
	KeyServer keyserver;
	CloudServer cloudserver;

	// Password blindness
	element_t alpha;
	element_init_G1(alpha, pairing);
	client.blindPassword(alpha);
	cout << "The client blinds the password and sends it to the key server!" << endl;

	// Password hardening
	element_t beta;
	element_init_G1(beta, pairing);
	keyserver.hardenPassword(beta, alpha, ID_u);
	cout << "Password Hardening Finished!" << endl;

	// Credential generation for cloud server
	string cred_cs;
	string cred_ks;
	string s_u;
	client.CredentialGen(s_u, cred_ks, cred_cs, alpha, beta, keyserver.public_key);
	// Register with cloud server
	cout << "The client ready to register with the cloud server!" << endl;
	cloudserver.store(ID_u, cred_cs, s_u);
    cout << "You have successfully registered with the cloud server!" << endl;
	// Register with key server
	cout << "The client ready to register with the key server!" << endl;
	keyserver.store(ID_u, cred_ks);
    cout << "You have successfully registered with the cloud server!" << endl;
}