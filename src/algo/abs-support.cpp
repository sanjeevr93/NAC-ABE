/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
 *
 * This file is part of ndnabac, a certificate management system based on NDN.
 *
 * ndnabac is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndnabac is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndnabac, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndnabac authors and contributors.
 */

#include "abs-support.hpp"
#include "pairing.hpp"
#include <ndn-cxx/util/logger.hpp>
#include <openssl/evp.h>

using namespace std;

namespace ndn {
namespace ndnabac {
namespace algo {

NDN_LOG_INIT(ndnabac.ABESupport);

void
ABSSupport::setup(PublicParams& pubParams, MasterKey& masterKey)
{
  bswabe_pub_t* pub;
  bswabe_msk_t* msk;
  bswabe_setup(&pub, &msk);

  pubParams.m_pub = bswabe_pub_serialize(pub);
  masterKey.m_msk = bswabe_msk_serialize(msk);
}

PrivateKey
ABSSupport::prvKeyGen(const PublicParams& pubParams, MasterKey& masterKey,
                      const std::vector<std::string>& attrList)
{
  // change list<string> to char**
  char** attrs = new char*[attrList.size() + 1];
  for (size_t i = 0; i < attrList.size(); i++) {
    char *cstr = new char[attrList[i].length() + 1];
    std::strcpy(cstr, attrList[i].c_str());
    cstr[attrList[i].length()] = 0;
    attrs[i] = cstr;
  }
  attrs[attrList.size()] = 0;

  bswabe_pub_t* pub = bswabe_pub_unserialize(pubParams.m_pub, 0);
  bswabe_msk_t* msk = bswabe_msk_unserialize(pub, masterKey.m_msk, 0);
  bswabe_prv_t* prv = bswabe_keygen(pub, msk, attrs);

  PrivateKey privateKey;
  privateKey.m_prv = bswabe_prv_serialize(prv);

/*  for (size_t i = 0; i < attrList.size(); i++) {
    delete [] attrs[i];
  }
  delete [] attrs; */
  return privateKey;
}

SignedMessage
ABSSupport::signs(const PublicParams& pubParams, PrivateKey& signingKey,
                  Buffer plainText, const std::string& policy)
{
  //unique_ptr<RNG> PRNG = nullptr;
  //unique_ptr<std::string> y = nullptr;
  bswabe_pub_t* pub = bswabe_pub_unserialize(pubParams.m_pub, 0);
  bswabe_prv_t* prv = bswabe_prv_unserialize(pub, signingKey.m_prv, 0);
  
  char *policyCharArray = new char[policy.length() + 1];
  strcpy(policyCharArray, policy.c_str());

  element_t m;
  bswabe_sgn_t* sgn = bswabe_sign(pub, prv, m, policyCharArray);
  SignedMessage result;
  result.m_sgn = bswabe_sgn_serialize(sgn);
  bswabe_sgn_free(sgn);
  delete [] policyCharArray;

  return result;

}

bool
ABSSupport::verification(const PublicParams& pubParams, SignedMessage signedMessage,
                         const std::string& policy, const std::string& signs )
{
  bool answer = 0;
  bswabe_pub_t* pub = bswabe_pub_unserialize(pubParams.m_pub, 0);
  element_t m;
  char *policyCharArray = new char[policy.length() + 1];
  strcpy(policyCharArray, policy.c_str());
  bswabe_sgn_t* sgn = bswabe_sgn_unserialize(pub, signedMessage.m_sgn, 0);

  answer = ((m, sgn, signedMessage.m_sgn->len) == 1);
  if(!answer) {
    NDN_LOG_ERROR("Verification error!" + std::string(bswabe_error()));
  }
  return answer;
}

} // namespace algo
} // namespace ndnabac
} // namespace ndn
