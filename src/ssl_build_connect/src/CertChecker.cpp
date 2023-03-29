#include "ssl_build_connect/CertChecker.h"
#include <iostream>

CertChecker::CertChecker(/* args */)
{
    store = X509_STORE_new();
    // 设置默认证书目录 
    X509_STORE_set_default_paths(store);
    trusted_chain = sk_X509_new_null();
    untrusted_chain = sk_X509_new_null();
    build_chain = sk_X509_new_null();

    // 加载受信任的证书(根证书)
    std::string rootPath = CA_DIR_ROOT + "key/root.crt";
    X509* root = CertChecker::getCert(rootPath);
    this->addToStore(root);
    this->addToChain(root,true);
}

CertChecker::~CertChecker()
{
    // 释放资源
    X509_STORE_free(store); 
    sk_X509_free(trusted_chain);
    sk_X509_free(untrusted_chain);
    sk_X509_free(build_chain);
}
X509* CertChecker::getCert(std::string certPath) {
    // 创建 BIO 对象，用于读取文件
    BIO* bio = BIO_new_file(certPath.c_str(), "r");
    if(bio == NULL) {
        std::cout << "读取文件出错" << std::endl;
        return nullptr;
    }
    X509* cert = nullptr; 
    PEM_read_bio_X509(bio, &cert, nullptr, nullptr);
    if(!cert) {
        std::cout << "解析文件出错" << std::endl;
    }
    // 关闭 BIO 对象
    BIO_free(bio);
    return cert;
}

bool CertChecker::addToChain(X509* cert,bool trust) {
    if(cert == nullptr) {
        return false;
    }
    // 入栈
    if(trust) {
        sk_X509_push(trusted_chain, cert);
    }
    else {
        sk_X509_push(untrusted_chain, cert);
    }
    return true;
}

bool CertChecker::addToStore(X509* cert) {
    // 将证书添加到 X509_STORE 中
    if (X509_STORE_add_cert(store, cert) != 1) {
        // 错误处理
        return false;
    }
    return true;
}

int verifyCallback(int ok, X509_STORE_CTX *ctx)
{
    // 自定义验证逻辑
    // 返回值为1表示验证成功，0表示验证失败
    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    char buf[256];
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);
    std::cout << "正在验证：" << buf << std::endl;
    
    if (!ok) {
        // 验证失败，打印错误信息
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        int err = X509_STORE_CTX_get_error(ctx);
        printf("Error at depth %d: %s\n", depth, buf);
        printf("  Error code %d (%s)\n", err, X509_verify_cert_error_string(err));
        return 0;
    }
    std::cout << "验证通过" << std::endl;
    return ok;
}

int CertChecker::verifyCert(X509* cert)
{
    // 初始化上下文
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if(ctx == nullptr) {
        std::cout << "初始化失败" << std::endl;
    }

    // 参数说明 (ctx, store, 待验证证书, 非信任的待验证证书链)
    if(!X509_STORE_CTX_init(ctx, store, cert, untrusted_chain)) {
        std::cout << "初始化上下文失败" << std::endl;
    }
    // 设置自定义验证回调函数
    // X509_STORE_CTX_set_verify_cb(ctx, verifyCallback);
    // 禁用 CRL 检查
    X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_PROXY_CERTS | X509_V_FLAG_IGNORE_CRITICAL);
    // 设置可信证书链
    // X509_STORE_CTX_trusted_stack(ctx, trusted_chain);
    // 验证证书链的可信性
    int result = X509_verify_cert(ctx);
    // int result = X509_verify(server_cert, store);
    if(result != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        std::cout << X509_verify_cert_error_string(err) << std::endl;
    }
    X509_STORE_CTX_free(ctx);
    return result;
}

// 构建证书链
STACK_OF(X509)* CertChecker::buildCertChain(X509* cert) {
    build_chain = sk_X509_new_null();

    // 创建一个验证器并设置一些参数
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        // 处理错误
        return NULL;
    }
    // 禁用 CRL 检查
    X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_PROXY_CERTS | X509_V_FLAG_IGNORE_CRITICAL);
    // 初始化上下文
    if (!X509_STORE_CTX_init(ctx, store, cert, untrusted_chain)) {
        // 处理错误
        return NULL;
    }
    // 设置自定义验证回调函数
    X509_STORE_CTX_set_verify_cb(ctx, verifyCallback);
    // X509_STORE_CTX_trusted_stack(ctx, trusted_chain);
    int ret = X509_verify_cert(ctx);
    if (ret != 1) {
        // 验证失败，处理错误
        int err = X509_STORE_CTX_get_error(ctx);
        // 处理错误码
        return NULL;
    }
    // 生成证书链并获取
    build_chain = X509_STORE_CTX_get1_chain(ctx);
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    return build_chain;
}

std::string CertChecker::x509_to_string(X509 *cert) {
    std::string cert_str;
    BIO *bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(bio, cert)) {
        char *cert_data;
        long cert_size = BIO_get_mem_data(bio, &cert_data);
        cert_str.assign(cert_data, cert_size);
    }
    BIO_free(bio);
    return cert_str;
}

X509* CertChecker::string_to_x509(const std::string& cert_str) {
    BIO* cert_bio = BIO_new_mem_buf(cert_str.data(), cert_str.size());
    if (cert_bio == nullptr) {
        return nullptr;
    }
    X509* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);
    return cert;
}