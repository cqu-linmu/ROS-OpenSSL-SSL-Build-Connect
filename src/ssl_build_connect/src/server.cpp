#include <ros/ros.h>
#include <signal.h>
#include <vector>
#include "ssl_build_connect/Tag.h"
#include "ssl_build_connect/record.h"
#include "ssl_build_connect/CertChecker.h"
#include "ssl_build_connect/KeyAgree.h"
#include "ssl_build_connect/Encrypt.h"

using namespace std;

// 用于访问工具类
CertChecker* certChecker = nullptr;
KeyAgree* keyAgree = nullptr;

// 用于保存对称加密密钥
string shared_key;

/**
 * 从本地读取证书，并构建证书链
*/
vector<string> getCertChain() {
    // 用于保存证书链
    vector<string> certs;

    // 读取服务器证书
    string serverCertPath = CA_DIR_SERVER + "server.crt";
    X509* server = CertChecker::getCert(serverCertPath);
    // 读取CA代理证书
    string agentCertPath = CA_DIR_AGENT + "key/agent.crt";
    X509* agent = CertChecker::getCert(agentCertPath);
    certChecker->addToChain(agent, false);
    // 构建证书链
    STACK_OF(X509)* chain = certChecker->buildCertChain(server);
    if (chain != NULL) {
        ROS_INFO("证书链构建通过");
    } else {
        ROS_ERROR("证书链构建失败");
        return certs;
    }
    // 将证书链解析进去字符串数组 certs
    int length = sk_X509_num(chain);
    cout << "证书链长:" << length << endl;
    for(int i=0;i<length;i++) {
        X509* tempCert = sk_X509_value(chain,i);
        string cert = CertChecker::x509_to_string(tempCert);
        certs.push_back(cert);
        // cout << cert << endl;
    }
    return certs;
}

/**
 * 回调函数
*/
bool requestCallback(ssl_build_connect::record::Request &req, ssl_build_connect::record::Response &res) {
    if(req.tag == TAG_HELLO) {
        ROS_INFO("服务器接收到 hello 消息: tag: %d data: %s", req.tag, req.data.c_str());
        ROS_INFO("服务器确认加密协议，并返回证书链");
        res.tag = TAG_HELLO;
        res.data = "RSA_DH_MD5";
        vector<string> certs = getCertChain();
        for(string cert : certs) {
            res.cert.push_back(cert);
        }
        ROS_INFO("服务器接发送 hello 消息: tag: %d data: %s", res.tag, res.data.c_str());
    }
    else if(req.tag == TAG_KEY) {
        ROS_INFO("服务器接收到 key 消息: tag: %d data: %s", req.tag, string_to_hex(req.data).c_str());
        keyAgree->setOtherKey(req.data);

        ROS_INFO("服务器获取公钥");
        res.tag = TAG_KEY;
        res.data = keyAgree->getPublicKey();

        ROS_INFO("服务器接发送 key 消息: tag: %d data: %s", res.tag,string_to_hex(res.data).c_str());

        shared_key = keyAgree->getShareKey();
        ROS_INFO("服务器生成对称加密密钥: %s",string_to_hex(shared_key).c_str());
    }
    else if(req.tag == TAG_FINISH) {
        ROS_INFO("服务器收到 finish 消息: tag: %d data: %s", req.tag, string_to_hex(req.data).c_str());
        string word = decrypt_AES(req.data, shared_key);
        ROS_INFO("解密数据：%s 长度为：%d",word.c_str(),(int)word.length());

        string returnWord = "hello client!";
        res.tag = TAG_FINISH;
        res.data = encrypt_AES(returnWord, shared_key);
        ROS_INFO("数据：%s 长度为：%d",returnWord.c_str(),(int)returnWord.length());
        ROS_INFO("服务器发送 finish 消息: tag: %d data: %s", res.tag, string_to_hex(res.data).c_str());
    }
    else {

    }
    return true;
}

int main(int argc, char** argv) {
    // 中文显示
    setlocale(LC_ALL,"");
    // 初始化服务器节点，并配置回调函数
    ros::init(argc, argv, "ssl_server");
    ros::NodeHandle n;
    ros::ServiceServer person_service = n.advertiseService("/ssl_build", requestCallback);

    // 创建工具类并赋值给全局指针
    CertChecker certCheckerL;
    KeyAgree keyAgreeL;
    certChecker = &certCheckerL;
    keyAgree = &keyAgreeL;

    ROS_INFO("服务器创建完成");
    ros::spin();
    return 0;
}