
/// \file   zpairing.h
///
/// \brief  Class definition for bilinear maps (or pairings).
///

#ifndef NDNABAC_ALGO_PAIRING_HPP
#define NDNABAC_ALGO_PAIRING_HPP

#include "algo-common.hpp"
#include "public-params.hpp"
#include "master-key.hpp"
#include "private-key.hpp"
#include "signed-message.hpp"

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <mutex>

namespace ndn {
namespace ndnabac {
namespace algo {

class Pairing {
public:
  Pairing(const std::string &pairingParams);
  Pairing(const Pairing &copyFrom);
  ~Pairing();
  void     initZP(ZP& z, uint32_t v);
  ZP       initZP();
  G1       initG1();
  G2       initG2();
  GT       initGT();

  ZP       randomZP(RNG *rng);
  G1       randomG1(RNG *rng);
  G2       randomG2(RNG *rng);

  GByteArray* hashToBytes(uint8_t*, uint32_t);
  GByteArray* hashFromBytes(GByteArray &buf, uint32_t target_len, uint8_t hash_prefix);

  G1       hashToG1(GByteArray*, std::string);
  GT       pairing(G1& g1, G2& g2);
  void     multi_pairing(GT& gt, std::vector<G1>& g1, std::vector<G2>& g2);

  std::string  getPairingParams() const;
  std::string  getCurveID() const;

protected:
  bool         isSymmetric;
  std::string  curveID;
  std::string  pairingParams;
};
}
}
}

#endif	// __PAIRING_H__