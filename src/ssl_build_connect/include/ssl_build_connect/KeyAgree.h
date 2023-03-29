#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>

using namespace std;

class KeyAgree {
    private:
        EC_KEY* ec_key;
        const EC_GROUP* group;
        EC_POINT* key_other;
        // ec_point 转为 string
        EC_POINT* ec_point_from_string(const string& str);
        // string 转为 ec_point
        string ec_point_to_string(const EC_POINT* point);
    public:
        KeyAgree();
        ~KeyAgree();
        const BIGNUM* getPrivateKey();
        string getPublicKey();
        void setOtherKey(string keyStr);
        string getShareKey();
};

