#include <ros/ros.h>
#include "ssl_build_connect/Tag.h"
#include "ssl_build_connect/record.h"
#include "ssl_build_connect/CertChecker.h"
#include "ssl_build_connect/KeyAgree.h"
#include "ssl_build_connect/Encrypt.h"

using namespace std;

KeyAgree keyAgree;
CertChecker certChecker;
ros::ServiceClient* serClient;
string shared_key;

bool tagHello();
bool tagKey();
bool tagFinish();

int main(int argc, char** argv) {
    // 中文显示
    setlocale(LC_ALL,"");
    ros::init(argc, argv, "ssl_client");

    ros::NodeHandle node;

    //发现/show_person服务后，创建client, 连接/show_person的服务
    ros::service::waitForService("/ssl_build");
    ros::ServiceClient ssl_client = node.serviceClient<ssl_build_connect::record>("/ssl_build");
    serClient = &ssl_client;
    bool res;
    res = tagHello();
    if(!res) {
        return -1;
    }
    res = tagKey();
    if(!res) {
        return -1;
    }
    res = tagFinish();
    return 0;
}
bool tagHello() {
    //初始化请求数据
    ssl_build_connect::record srv;

    srv.request.tag = TAG_HELLO;
    srv.request.data = "DH_MD5";

    ROS_INFO("客户端发送 hello 消息: tag: %d data: %s", srv.request.tag, string_to_hex(srv.request.data).c_str());
    serClient->call(srv);
    ROS_INFO("客户端接收 hello 消息: tag: %d data: %s", srv.response.tag, string_to_hex(srv.response.data).c_str());
    ROS_INFO("客户端正在验证服务器证书链");

    // 使用 cert 保存服务器证书
    X509* cert = nullptr;
    // 获取证书链长度
    int cert_count = srv.response.cert.size();
    // 遍历证书字符串
    for(string certString:srv.response.cert) {
        // 将字符串重新解析为 X509 证书
        X509* temp = CertChecker::string_to_x509(certString);
        if(temp == nullptr) {
            ROS_ERROR("解析失败");
            return false;
        }
        // 使用 cert 接收服务器证书
        if(cert == nullptr) {
            cert = temp;
        }
        // 将 证书添加到 非信任证书链
        certChecker.addToChain(temp,false);
        // 打印 解析文件消息
        char buf[256];
        X509_NAME_oneline(X509_get_subject_name(temp), buf, 256);
        cout << "已解析：" << buf << endl;
    }
    // 验证证书
    int res = certChecker.verifyCert(cert);
    if (res == 1) {
        ROS_INFO("证书验证通过");
    } else {
        ROS_ERROR("证书验证失败");
        return false;
    }
    return true;
    
}
bool tagKey() {
    //初始化请求数据
    ssl_build_connect::record srv;

    srv.request.tag = TAG_KEY;
    srv.request.data = keyAgree.getPublicKey();

    ROS_INFO("客户端发送 key 消息: tag: %d data: %s", srv.request.tag, string_to_hex(srv.request.data).c_str());
    serClient->call(srv);
    ROS_INFO("客户端接收 key 消息: tag: %d data: %s", srv.response.tag, string_to_hex(srv.response.data).c_str());
    keyAgree.setOtherKey(srv.response.data);
    shared_key = keyAgree.getShareKey();
    ROS_INFO("客户端生成对称加密密钥(转为十六进制): %s",string_to_hex(shared_key).c_str());
    return true;
}
bool tagFinish() {
    //初始化请求数据
    ssl_build_connect::record srv;

    string word = "hello server!";
    ROS_INFO("数据：%s 长度为：%d",word.c_str(),(int)word.length());
    string str = encrypt_AES(word,shared_key);
    srv.request.tag = TAG_FINISH;
    srv.request.data = str;

    ROS_INFO("客户端发送 finish 消息: tag: %d data: %s", srv.request.tag, string_to_hex(srv.request.data).c_str());
    serClient->call(srv);
    ROS_INFO("客户端接收 finish 消息: tag: %d data: %s", srv.response.tag, string_to_hex(srv.response.data).c_str());
    string returnWord = decrypt_AES(srv.response.data, shared_key);
    ROS_INFO("解密数据：%s 长度为：%d",returnWord.c_str(),(int)returnWord.length());
    return true;
}