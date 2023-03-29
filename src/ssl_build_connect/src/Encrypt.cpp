#include "ssl_build_connect/Encrypt.h"

/**
 * 基于AES进行加密（CBC模式）
*/
string encrypt_AES(const string str, const string key) {
    // 创建加密算法对象
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    // 转换密钥格式
    unsigned char* uc_key = (unsigned char*)key.c_str();
    // 初始向量，由于 使用的是 aes_256 所以 密钥 和 初始向量的长度均需要为 32 字节 
    unsigned char iv[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01};
    // 转换输入待加密文本格式
    unsigned char* in = (unsigned char*)str.c_str();
    int inlen = strlen((const char*)in);
    // 输出缓冲区
    unsigned char out[1024];
    int outlen = 0;
	// 创建加密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // 初始化加密操作
    EVP_EncryptInit_ex(ctx, cipher, NULL, uc_key, iv);
    // 执行加密操作
    EVP_EncryptUpdate(ctx, out, &outlen, in, inlen);
    // 结束加密操作
    int tmplen = 0;
    EVP_EncryptFinal_ex(ctx, out + outlen, &tmplen);
    outlen += tmplen;
    // 清理加密上下文
    EVP_CIPHER_CTX_free(ctx);
    // 加密结果转换为字符串
    string result((char*)(out));
    result = result.substr(0,outlen);
    cout << "encrypted data: " << result << endl;
    return result;
}

/**
 * 基于AES进行解密（CBC模式）
*/
string decrypt_AES(const string aes_str, const string key) {
    // 创建解密算法对象
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    // 转换密钥格式
    unsigned char* uc_key = (unsigned char*)key.c_str();
    // 初始向量，由于 使用的是 aes_256 所以 密钥 和 初始向量的长度均需要为 32 字节 
    unsigned char iv[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01};
    // 转换输入待解密文本格式
    unsigned char* in = (unsigned char*)aes_str.c_str();
    int inlen = strlen((const char*)in);
    // 创建解密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // 初始化解密操作
    EVP_DecryptInit_ex(ctx, cipher, NULL, uc_key, iv);
    // 执行解密操作
    unsigned char out[1024];
    int outlen = 0;
    EVP_DecryptUpdate(ctx, out, &outlen, in, inlen);
    // 结束解密操作
    int tmplen = 0;
    EVP_DecryptFinal_ex(ctx, out + outlen, &tmplen);
    outlen += tmplen;
    // 清理解密上下文
    EVP_CIPHER_CTX_free(ctx);
    // 解密结果转换为字符串
    string result((char*)(out));
    // 截取字符串
    result = result.substr(0,outlen);
    cout << "decrypted data: " << result << endl;
    return result;
}

//转十六进制
string string_to_hex(const string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	string output;
	output.reserve(2 * len);//预分配两倍的空间
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];//存储第一个字符
		//该char字符的二进制右移四位获取十六进制的第一个字符
		output.push_back(lut[c >> 4]);
		//清楚该char字符的高4位，保留低四位
		output.push_back(lut[c & 15]);
	}
	return output;
}