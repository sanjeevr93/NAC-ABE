/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2017, Regents of the University of California.
 *
 * This file is part of ChronoShare, a decentralized file sharing application over NDN.
 *
 * ChronoShare is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ChronoShare is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ChronoShare, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ChronoShare authors and contributors.
 */

#include "attribute-authority.hpp"

#include "test-common.hpp"
#include "dummy-forwarder.hpp"

#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace ndnabac {
namespace tests {

namespace fs = boost::filesystem;

class TestAttributeAuthorityFixture : public IdentityManagementTimeFixture
{
public:
  TestAttributeAuthorityFixture()
    : attrAuthorityPrefix("/access-controller")
  {
    auto id = addIdentity(attrAuthorityPrefix);
    auto key = id.getDefaultKey();
    cert = key.getDefaultCertificate();
  }

public:
  Name attrAuthorityPrefix;
  security::v2::Certificate cert;
};

BOOST_FIXTURE_TEST_SUITE(TestAttributeAuthority, TestAttributeAuthorityFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  util::DummyClientFace face(m_io, {true, true});
  AttributeAuthority aa(cert, face, m_keyChain);
  BOOST_CHECK(aa.m_pubParams.m_pub != nullptr);
  BOOST_CHECK(aa.m_masterKey.m_msk != nullptr);
}

BOOST_AUTO_TEST_CASE(onPublicParams)
{
  util::DummyClientFace face(m_io, {true, true});
  AttributeAuthority aa(cert, face, m_keyChain);
  Name interestName = attrAuthorityPrefix;
  Interest request(interestName.append(AttributeAuthority::PUBLIC_PARAMS));
  auto requiredBuffer = aa.m_pubParams.toBuffer();

  advanceClocks(time::milliseconds(20), 60);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      auto block = response.getContent();
      Buffer contentBuffer(block.value(), block.value_size());
      algo::PublicParams pubParams;
      pubParams.fromBuffer(contentBuffer);
      auto buffer = pubParams.toBuffer();

      BOOST_CHECK_EQUAL_COLLECTIONS(buffer.begin(), buffer.end(),
                                    requiredBuffer.begin(), requiredBuffer.end());
    });
  face.receive(request);

  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(onPrvKey)
{
  Name consumerName("/consumer");
  RsaKeyParams params;
  auto consumerId = addIdentity(consumerName, params);
  auto consumerKey = consumerId.getDefaultKey();
  auto consumerCert = consumerKey.getDefaultCertificate();

  std::list<std::string> attrList = {"attr1", "attr2", "attr3", "attr4", "attr5",
                                     "attr6", "attr7", "attr8", "attr9", "attr10"};

  util::DummyClientFace face(m_io, {true, true});
  AttributeAuthority aa(cert, face, m_keyChain);
  aa.m_trustConfig.m_trustAnchors.push_back(consumerCert);
  aa.m_tokens.insert(std::pair<Name, std::list<std::string>>(consumerName, attrList));

  Name interestName = attrAuthorityPrefix;
  interestName.append("DKEY").append(consumerName.wireEncode());
  Interest interest(interestName);
  m_keyChain.sign(interest, security::signingByCertificate(consumerCert));

  advanceClocks(time::milliseconds(20), 60);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      std::cout << response;
      std::cout << "dkey Data length: " << response.wireEncode().size() << std::endl;
      std::cout << "dkey Name length: " << response.getName().wireEncode().size() << std::endl;
      std::cout << "=================================\n";
    });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
