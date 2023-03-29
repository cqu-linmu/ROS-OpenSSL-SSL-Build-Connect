#pragma once

#include <string>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>

using namespace std;

string encrypt_AES(const string str, const string key);

string decrypt_AES(const string aes_str, const string key);

std::string string_to_hex(const std::string& input);