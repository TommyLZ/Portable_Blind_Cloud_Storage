#include "Give.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
using namespace std;

extern pairing_t pairing;

void Give(string& pwd, string& id) {
    cout << "**********************************Give phase**********************************" << endl;
	// User inputs password & ID to the Client
	// Object instantiation
	Client client(pwd, id);
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
    string s_id;
    string r_id;
	string cred_cs;
    client.loginToCS_Give(r_id, s_id, cred_cs, id, b);
	cout << "The client ready to log in the cloud server!" << endl;

	// Cloud server authenticates the client
    cloudserver.authenInGive_CS(s_id, r_id, id, cred_cs);
    cout << "You have successfully logged in the cloud server!" << endl;

	string t;
	string k_1;
	string k_2;
	string ct;
	string tag;
	client.loginToKS_Give(t, k_1, k_2, ct, tag, s_id, r_id);
	cout << "The client ready to log in the key server!" << endl;

    keyserver.authenInGive_KS(id, t, ct, tag);
    cout << "You have successfully logged in the cloud server!" << endl;
}