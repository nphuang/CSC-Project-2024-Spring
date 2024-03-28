#pragma once
#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

#include <memory>
#include <span>
#include <string>
#include <vector>
// ESP_AALG class for ESP authentication algorithm
class ESP_AALG {
public:
  // Constructor
  ESP_AALG(int algorithmCode, std::span<uint8_t> _key);

  // Hash the message
  std::vector<uint8_t> hash(std::span<uint8_t> message);
  // Verify the message
  bool verify(std::span<const uint8_t> message);
  // Check if the algorithm is empty
  bool empty() const { return algorithm == nullptr; }
  // Get the algorithm name
  std::string name() { return algorithm->AlgorithmName(); }
  // Get the algorithm provider
  std::string provider() { return algorithm->AlgorithmProvider(); }
  // Get the hash length
  uint32_t hashLength() { return digestSize; }

private:
  uint32_t digestSize; // size of the hash
  std::unique_ptr<CryptoPP::HMAC_Base> algorithm; // HMAC algorithm
};

class ESP_EALG {
public:
  // Constructor
  ESP_EALG(int algorithmCode, std::span<uint8_t> _key);
  // Encrypt the message
  template <typename ENC, typename DEC, int blockSize>
  void makeCipher(CryptoPP::SecByteBlock* key) {
    CryptoPP::SecByteBlock iv(_ivLength);
    _blockSize = blockSize;
    enc = std::make_unique<ENC>();
    if (enc->IVRequirement() == CryptoPP::SimpleKeyingInterface::NOT_RESYNCHRONIZABLE) {
      enc->SetKey(*key, key->size());
    } else {
      enc->SetKeyWithIV(*key, key->size(), iv, iv.size());
    }
    dec = std::make_unique<DEC>();
    if (dec->IVRequirement() == CryptoPP::SimpleKeyingInterface::NOT_RESYNCHRONIZABLE) {
      dec->SetKey(*key, key->size());
    } else {
      dec->SetKeyWithIV(*key, key->size(), iv, iv.size());
    }
  }
  std::vector<uint8_t> encrypt(std::span<uint8_t> message);
  std::vector<uint8_t> decrypt(std::span<const uint8_t> message);
  bool empty() const { return enc == nullptr; }
  std::string name() { return enc->AlgorithmName(); }
  std::string provider() { return enc->AlgorithmProvider(); }
  uint32_t ivLength() { return _ivLength; }
  uint32_t blockSize() { return _blockSize; }

private:
  static CryptoPP::AutoSeededRandomPool prng;
  uint32_t _blockSize;
  uint32_t _ivLength;
  std::unique_ptr<CryptoPP::CipherModeBase> enc;
  std::unique_ptr<CryptoPP::CipherModeBase> dec;
};
