#include "ssl_build_connect/KeyAgree.h"
#include "ssl_build_connect/Encrypt.h"

KeyAgree::KeyAgree() {
    // 指定曲线
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        cerr << "Failed to create EC key." << endl;
        return;
    }
    // 生成密钥对
    if (EC_KEY_generate_key(ec_key) != 1) {
        cerr << "Failed to generate EC key." << endl;
        return;
    }
    // 获取密钥组
    group = EC_KEY_get0_group(ec_key);
}
KeyAgree::~KeyAgree() {
    // 释放空间
    EC_KEY_free(ec_key);
}
const BIGNUM* KeyAgree::getPrivateKey() {
    // 获取私钥
    const BIGNUM* key = EC_KEY_get0_private_key(ec_key);
    cout << "Private key:" << endl;
    BN_print_fp(stdout, key);
    cout << endl;
    return key;
}
string KeyAgree::getPublicKey() {
    // 获取私钥
    const EC_POINT* key = EC_KEY_get0_public_key(ec_key);
    cout << "Public key:" << endl;
    
    // 密钥转为字符串
    string str = ec_point_to_string(key);
    cout << string_to_hex(str) << endl;
    return str;
}

void KeyAgree::setOtherKey(string keyStr) {
    // 设置对等公钥
    EC_POINT* key = ec_point_from_string(keyStr);
    key_other = key;
}

string KeyAgree::getShareKey() {
    // 设置对称密钥长度
    size_t shared_key_len = 32;
    // 用于保存对称密钥
    vector<unsigned char> shared_key(shared_key_len);
    // 生成对称密钥 (密钥缓存区，密钥长度，对等公钥，本地密钥对)
    if (ECDH_compute_key(shared_key.data(), shared_key.size(), key_other, ec_key, NULL) != shared_key_len) {
        cerr << "Failed to compute shared key." << endl;
        return "";
    }
    // 转为字符串
    string str(shared_key.begin(), shared_key.end());
    return str;
}


EC_POINT* KeyAgree::ec_point_from_string(const string& str) {
    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        cerr << "Failed to create EC point." << endl;
        return nullptr;
    }
    if (EC_POINT_oct2point(group, point, reinterpret_cast<const unsigned char*>(str.c_str()), str.length(), nullptr) != 1) {
        cerr << "Failed to convert EC point from string." << endl;
        EC_POINT_free(point);
        return nullptr;
    }
    return point;
}

string KeyAgree::ec_point_to_string(const EC_POINT* point) {
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (len == 0) {
        cerr << "Failed to get size of EC point buffer." << endl;
        return "";
    }
    string str(len, '\0');
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast<unsigned char*>(&str[0]), len, nullptr) != len) {
        cerr << "Failed to convert EC point to string." << endl;
        return "";
    }
    return str;
}