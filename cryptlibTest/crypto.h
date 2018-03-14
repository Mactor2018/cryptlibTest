#ifndef CRYPTO_H
#define CRYPTO_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wextra"
#include <hex.h>
#include <osrng.h>
#include <pssr.h>
#include <rsa.h>
#include <whrlpool.h>
#pragma GCC diagnostic pop

#include <string>

// see http://www.cryptopp.com/wiki/RSA

struct KeyPairHex {
  std::string publicKey;
  std::string privateKey;
};

using Signer   = CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::Whirlpool>::Signer;
using Verifier = CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::Whirlpool>::Verifier;

//==============================================================================
inline KeyPairHex RsaGenerateHexKeyPair(unsigned int aKeySize) {
  KeyPairHex keyPair;

  // PGP Random Pool-like generator
  CryptoPP::AutoSeededRandomPool rng;

  // generate keys
  CryptoPP::RSA::PrivateKey privateKey;
  privateKey.GenerateRandomWithKeySize(rng, aKeySize);
  CryptoPP::RSA::PublicKey publicKey(privateKey);

  // save keys
  publicKey.Save( CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(keyPair.publicKey)).Ref());
  privateKey.Save(CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(keyPair.privateKey)).Ref());

  return keyPair;
}

//==============================================================================
inline std::string RsaSignString(const std::string &aPrivateKeyStrHex,
                                 const std::string &aMessage) {

  // decode and load private key (using pipeline)
  CryptoPP::RSA::PrivateKey privateKey;
  privateKey.Load(CryptoPP::StringSource(aPrivateKeyStrHex, true,
                                         new CryptoPP::HexDecoder()).Ref());

  // sign message
  std::string signature;
  Signer signer(privateKey);
  CryptoPP::AutoSeededRandomPool rng;

  CryptoPP::StringSource ss(aMessage, true,
                            new CryptoPP::SignerFilter(rng, signer,
                              new CryptoPP::HexEncoder(
                                new CryptoPP::StringSink(signature))));

  return signature;
}

//==============================================================================
inline bool RsaVerifyString(const std::string &aPublicKeyStrHex,
                            const std::string &aMessage,
                            const std::string &aSignatureStrHex) {

  // decode and load public key (using pipeline)
  CryptoPP::RSA::PublicKey publicKey;
  publicKey.Load(CryptoPP::StringSource(aPublicKeyStrHex, true,
                                        new CryptoPP::HexDecoder()).Ref());

  // decode signature
  std::string decodedSignature;
  CryptoPP::StringSource ss(aSignatureStrHex, true,
                            new CryptoPP::HexDecoder(
                              new CryptoPP::StringSink(decodedSignature)));

  // verify message
  bool result = false;
  Verifier verifier(publicKey);
  CryptoPP::StringSource ss2(decodedSignature + aMessage, true,
                             new CryptoPP::SignatureVerificationFilter(verifier,
                               new CryptoPP::ArraySink((CryptoPP::byte*)&result,
                                                       sizeof(result))));

  return result;
}

inline std::string sha256_hex(const std::string & str)
{
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(digest, (CryptoPP::byte*)&str[0], str.size());

    std::string ret;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(ret));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return ret;
}

#endif // CRYPTO_H