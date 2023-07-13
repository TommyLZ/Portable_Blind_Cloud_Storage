#include "Decryption.h"

#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include <cryptopp/osrng.h>
#include <pbc/pbc.h>

extern pairing_t pairing;

void Decryption(string &psw, string &id){
    cout << "***********************************Decryption Phase*********************************" << endl;

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

    // Encrypt the file
    element_t c0;
    element_init_G1(c0, pairing);
    element_t c1;
    element_init_G1(c1, pairing);
    element_t hr1;
    element_init_G1(hr1, pairing);
	element_t hs1;
    element_init_G1(hs1, pairing);

    element_t mk;
    element_init_G1(mk, pairing);
    
    cloudserver.decrypt(c0, cred_cs, hr1, hs1);
    keyserver.decrypt(c1, c0);
    cloudserver.key_Recover(mk, c1, hr1, hs1, keyserver.public_key);
	cout << "The key recovery is finished!" << endl;

	// CryptoPP::byte iv[16 * 16];
	// AutoSeededRandomPool prng;
	// prng.GenerateBlock(iv, 16 * 16);
	
	// cloudserver.dataEncryption(mk, iv);
	// cout << "The applicaiton data is encrypted and outsourced successfully!" << endl;
	// cloudserver.dataDecryption(mk, iv);
	// cout << "The applicaiton data is recovered successfully!" << endl;
}