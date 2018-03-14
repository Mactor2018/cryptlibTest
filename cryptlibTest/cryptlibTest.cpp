// cryptlibTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

//For AES encrypt
#include "default.h" 
#include "cryptlib.h"
#include "filters.h"
#include "bench.h"
#include "osrng.h"
#include "hex.h"
#include "modes.h"
#include "files.h"

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "dll.h"
#include "config.h"
#include "aes.h"
#include "md5.h"
#include "ripemd.h"
#include "rng.h"
#include "gzip.h"
#include "randpool.h"
#include "ida.h"
#include "base64.h"
#include "socketft.h"
#include "wait.h"
#include "factory.h"
#include "tiger.h"
#include "smartptr.h"
#include "pkcspad.h"
#include "stdcpp.h"
#include "ossig.h"
#include "trap.h"
#include "validate.h"

#include <iostream>
#include <sstream>
#include <locale>
#include <ctime>
#include <string>
#include "cryptlib.h"
#include <sha.h>
#include <hex.h>

using namespace CryptoPP;
#pragma comment(lib, "lib\\cryptlib.lib") 

using namespace std;

void GenerateRSAKey();
void Sign();
void Verify();
string sha256_hex(const string & str);

void main() {
    //GenerateRSAKey();
    //Sign();
    //Verify();

    //auto sha256 = sha256_hex("original string");
    //cout << "str     = " << "original string" << endl << "sha 256 = " << sha256 << endl;


    getchar();
}

//string sha256_hex(const string & str)
//{
//    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
//    CryptoPP::SHA256().CalculateDigest(digest, (CryptoPP::byte*)&str[0], str.size());
//
//    string ret;
//    CryptoPP::HexEncoder encoder;
//    encoder.Attach(new CryptoPP::StringSink(ret));
//    encoder.Put(digest, sizeof(digest));
//    encoder.MessageEnd();
//
//    return ret;
//}

//void GenerateRSAKey()
//{
//    // InvertibleRSAFunction is used directly only because the private key
//    // won't actually be used to perform any cryptographic operation;
//    // otherwise, an appropriate typedef'ed type from rsa.h would have been used.
//    AutoSeededRandomPool rng;
//    InvertibleRSAFunction privkey;
//    privkey.Initialize(rng, 1024);
//
//    // With the current version of Crypto++, MessageEnd() needs to be called
//    // explicitly because Base64Encoder doesn't flush its buffer on destruction.
//    Base64Encoder privkeysink(new FileSink("privkey.txt"));
//    privkey.DEREncode(privkeysink);
//    privkeysink.MessageEnd();
//
//    // Suppose we want to store the public key separately,
//    // possibly because we will be sending the public key to a third party.
//    RSAFunction pubkey(privkey);
//
//    Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
//    pubkey.DEREncode(pubkeysink);
//    pubkeysink.MessageEnd();
//
//}
//
//void Sign()
//{
//    string strContents = "A message to be signed";
//    //FileSource("tobesigned.dat", true, new StringSink(strContents));
//
//    AutoSeededRandomPool rng;
//
//    //Read private key
//    CryptoPP::ByteQueue bytes;
//    FileSource file("privkey.txt", true, new Base64Decoder);
//    file.TransferTo(bytes);
//    bytes.MessageEnd();
//    RSA::PrivateKey privateKey;
//    privateKey.Load(bytes);
//
//    //Sign message
//    RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
//    SecByteBlock sbbSignature(privkey.SignatureLength());
//    privkey.SignMessage(
//        rng,
//        (CryptoPP::byte const*)strContents.data(),
//        strContents.size(),
//        sbbSignature);
//
//    //Save result
//    FileSink sink("signed.dat");
//    sink.Put((CryptoPP::byte const*)strContents.data(), strContents.size());
//    FileSink sinksig("sig.dat");
//    sinksig.Put(sbbSignature, sbbSignature.size());
//}
//
//void Verify()
//{
//    //Read public key
//    CryptoPP::ByteQueue bytes;
//    FileSource file("pubkey.txt", true, new Base64Decoder);
//    file.TransferTo(bytes);
//    bytes.MessageEnd();
//    RSA::PublicKey pubKey;
//    pubKey.Load(bytes);
//
//    RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);
//
//    //Read signed message
//    string signedTxt;
//    FileSource("signed.dat", true, new StringSink(signedTxt));
//    string sig;
//    FileSource("sig.dat", true, new StringSink(sig));
//
//    string combined(signedTxt);
//    combined.append(sig);
//
//    //Verify signature
//    try
//    {
//        StringSource(combined, true,
//            new SignatureVerificationFilter(
//                verifier, NULL,
//                SignatureVerificationFilter::THROW_EXCEPTION
//            )
//        );
//        cout << "Signature OK" << endl;
//    }
//    catch (SignatureVerificationFilter::SignatureVerificationFailed &err)
//    {
//        cout << err.what() << endl;
//    }
//
//}