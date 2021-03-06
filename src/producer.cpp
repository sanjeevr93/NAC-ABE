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

#include "producer.hpp"
#include "attribute-authority.hpp"
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndnabac {

NDN_LOG_INIT(ndnabac.producer);

const Name Producer::SET_POLICY = "/SET_POLICY";

//public
Producer::Producer(const security::v2::Certificate& identityCert, Face& face,
                   security::v2::KeyChain& keyChain, const Name& attrAuthorityPrefix,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_attrAuthorityPrefix(attrAuthorityPrefix)
  , m_repeatAttempts(repeatAttempts)
{
  // prefix registration
  auto filterId = m_face.setInterestFilter(Name(m_cert.getIdentity()).append(SET_POLICY),
                                           bind(&Producer::onPolicyInterest, this, _2));
  NDN_LOG_DEBUG("set prefix:" << m_cert.getIdentity());
  m_interestFilterIds.push_back(filterId);
  fetchPublicParams();
}

Producer::~Producer()
{
  for (auto prefixId : m_interestFilterIds) {
    prefixId.cancel();
  }
}

void
Producer::onAttributePubParams(const Interest& request, const Data& pubParamData)
{
  NDN_LOG_INFO("Get public parameters");
  Name attrAuthorityKey = pubParamData.getSignature().getKeyLocator().getName();
  for (auto anchor : m_trustConfig.m_trustAnchors) {
    if (anchor.getKeyName() == attrAuthorityKey) {
      BOOST_ASSERT(security::verifySignature(pubParamData, anchor));
      break;
    }
  }
  auto block = pubParamData.getContent();
  m_pubParamsCache.fromBuffer(Buffer(block.value(), block.value_size()));
}

void
Producer::produce(const Name& dataPrefix, const std::string& accessPolicy,
                  const uint8_t* content, size_t contentLen,
                  const SuccessCallback& onDataProduceCb, const ErrorCallback& errorCallback)
{
  // do encryption
  if (m_pubParamsCache.m_pub == nullptr) {
    errorCallback("public key missing");

    NDN_LOG_INFO("public parameters doesn't exist" );
  }
  else {
    NDN_LOG_INFO("encrypt data:"<<dataPrefix );
    auto cipherText = algo::ABESupport::encrypt(m_pubParamsCache, accessPolicy,
                                                Buffer(content, contentLen));

    Name ckName = security::v2::extractIdentityFromCertName(m_cert.getName());
    ckName.append("CK").append(std::to_string(random::generateSecureWord32()));

    Name dataName = m_cert.getIdentity();
    dataName.append(dataPrefix);
    Data data(dataName);
    auto dataBlock = makeEmptyBlock(tlv::Content);
    dataBlock.push_back(cipherText.makeDataContent());
    dataBlock.push_back(ckName.wireEncode());
    dataBlock.encode();
    data.setContent(dataBlock);
    m_keyChain.sign(data, signingByCertificate(m_cert));

    std::cout << data;
    std::cout << "Content Data length: " << data.wireEncode().size() << std::endl;
    std::cout << "Content Name length: " << data.getName().wireEncode().size() << std::endl;
    std::cout << "=================================\n";

    Name ckDataName = ckName;
    ckDataName.append("ENC-BY").append(accessPolicy);
    Data ckData(ckDataName);
    ckData.setContent(cipherText.makeCKContent());
    m_keyChain.sign(ckData, signingByCertificate(m_cert));

    std::cout << ckData;
    std::cout << "CK Data length: " << ckData.wireEncode().size() << std::endl;
    std::cout << "CK Name length: " << ckData.getName().wireEncode().size() << std::endl;
    std::cout << "=================================\n";

    onDataProduceCb(data);
  }
}

void
Producer::produce(const Name& dataPrefix, const uint8_t* content, size_t contentLen,
                  const SuccessCallback& onDataProduceCb, const ErrorCallback& errorCallback)
{
  // Encrypt data based on data prefix.
  auto it = m_policyCache.find(dataPrefix);
  if (it == m_policyCache.end()) {
    errorCallback("policy missing");
    NDN_LOG_INFO("policy doesn't exist");
    return;
  }
  produce(dataPrefix, it->second, content, contentLen, onDataProduceCb, errorCallback);

}

//private:
void
Producer::onPolicyInterest(const Interest& interest)
{
  //*** need verify signature ****
  NDN_LOG_DEBUG("on policy Interest:"<<interest.getName());
  NDN_LOG_INFO("on policy Interest:"<<interest.getName());
  Name dataPrefix = interest.getName().getSubName(2,1);
  // Name policy = interest.getName().getSubName(3,1);
  // _LOG_DEBUG(dataPrefix<<", "<<policy);

  std::pair<std::map<Name,std::string>::iterator,bool> ret;
  ret = m_policyCache.insert(std::pair<Name, std::string>(Name(dataPrefix),
                                                          encoding::readString(interest.getName().at(3))));

  Data reply;
  reply.setName(interest.getName());
  if (ret.second==false) {
    NDN_LOG_DEBUG("dataPrefix already exist");

    NDN_LOG_INFO("insert data prefix "<<dataPrefix<<" policy failed");
    reply.setContent(makeStringBlock(tlv::Content, "exist"));
  }
  else {
    NDN_LOG_DEBUG("insert success");
    NDN_LOG_INFO("insert data prefix "<<dataPrefix<<" with policy "<<encoding::readString(interest.getName().at(3)) );
    reply.setContent(makeStringBlock(tlv::Content, "success"));
  }
  NDN_LOG_DEBUG("before sign");
  m_keyChain.sign(reply, signingByCertificate(m_cert));
  NDN_LOG_DEBUG("after sign");
  m_face.put(reply);
}

void
Producer::fetchPublicParams()
{
  // fetch pub parameters
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(AttributeAuthority::PUBLIC_PARAMS);
  Interest interest(interestName);
  interest.setMustBeFresh(true);

  NDN_LOG_INFO("Requeset public parameters:"<<interest.getName());
  m_face.expressInterest(interest, std::bind(&Producer::onAttributePubParams, this, _1, _2),
                         [=](const Interest&, const lp::Nack&){},
                         [=](const Interest&){});
}

} // namespace ndnabac
} // namespace ndn
