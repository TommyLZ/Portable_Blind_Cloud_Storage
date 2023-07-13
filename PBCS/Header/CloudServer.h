#include <iostream>

using namespace std;

class CloudServer {
public:
    CloudServer();

    void store(string& id, string& cred_cs, string& s_id);

    void authenInGive_CS(string& s_u, string& r_id, string& id, string& cred_cs);

    void authenInTake_CS(string& s_id, string& r_id, string& id, string& cred_cs);
};