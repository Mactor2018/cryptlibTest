// cryptlibTest.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include "crypto.h"
#include "resource.h"

using namespace std;


void main()
{
    std::string licContent("INCREMENT MOD MOD_ID 0.8010 2019-3-1 uncounted ISSUED=2018-3-1");
    cout << "licContent: " << licContent << endl;

    //Step 1: hashҪ���ܵ��ַ���Ϊ�̶�����
    string sha256Message = sha256_hex(licContent);
    std::cout << "sha256Message:" << sha256Message << endl;

    //Step 2: ʹ��˽Կ�������ַ���
    string privateKey = PRIVATE_KEY;
    std::cout << "Private key: " << std::endl << privateKey << std::endl;
    string signature(RsaSignString(privateKey, sha256Message));
    std::cout << "Signature:" << std::endl << signature << std::endl;
    
    
    //Step 3: ʹ�ù�Կ�������ַ���
    string publicKey = PUBLIC_KEY;
    std::cout << "Public key: " << std::endl << publicKey << "\n" << std::endl;

    if (RsaVerifyString(publicKey, sha256Message, signature)) {
        std::cout << "Signatue valid." << std::endl;
    }
    else {
        std::cout << "Signatue invalid." << std::endl;
    }

    getchar();
}
