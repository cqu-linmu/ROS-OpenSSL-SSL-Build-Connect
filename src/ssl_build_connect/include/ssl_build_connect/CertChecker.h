#pragma once

#include "ssl_build_connect/Const.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

class CertChecker {
    private:
        // 可信证书库
        X509_STORE* store;
        // 可信证书链
        STACK_OF(X509)* trusted_chain;
        // 非可信证书链
        STACK_OF(X509)* untrusted_chain;
        // 构建的证书链
        STACK_OF(X509)* build_chain;
        
    public:
        // 无参构造
        CertChecker();
        // 析构函数
        ~CertChecker();
        // 从文件中读取证书
        static X509* getCert(std::string certPath);
        // 将 X509 证书转化为字符串
        static std::string x509_to_string(X509 *cert);
        // 从字符串中解析出 X509 证书
        static X509* string_to_x509(const std::string& cert_str);
        // 添加进入可信证书库
        bool addToStore(X509* cert);
        // 添加进入证书链 trust: 是否可信
        bool addToChain(X509* cert,bool trust);
        // 校验证书
        int verifyCert(X509* cert);
        // 校验证书并构建证书链
        STACK_OF(X509)* buildCertChain(X509* cert);
};



