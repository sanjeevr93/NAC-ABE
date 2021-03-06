/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2018,  Regents of the University of California
 *
 * This file is part of NAC (Name-based Access Control for NDN).
 * See AUTHORS.md for complete list of NAC authors and contributors.
 *
 * NAC is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NAC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NAC, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "data-enc-dec.hpp"
#include "aes.hpp"
#include "rsa.hpp"

namespace ndn {
namespace ndnabac {

Block
encryptDataContentWithCK(const uint8_t* payload, size_t payloadLen,
                         const uint8_t* key, size_t keyLen)
{
  // first create AES key and encrypt the payload
  AesKeyParams param;
  auto aesKey = Aes::generateKey(param);
  auto iv = Aes::generateIV();
  auto encryptedPayload = Aes::encrypt(aesKey.data(), aesKey.size(),
                                               payload, payloadLen, iv);

  // second use RSA key to encrypt the AES key
  auto encryptedAesKey = Rsa::encrypt(key, keyLen, aesKey.data(), aesKey.size());

  // create the content block
  auto content = makeEmptyBlock(tlv::Content);
  content.push_back(makeBinaryBlock(TLV_EncryptedContent,
                                    encryptedPayload.data(), encryptedPayload.size()));

  content.push_back(makeBinaryBlock(TLV_EncryptedAesKey,
                                    encryptedAesKey.data(), encryptedAesKey.size()));

  content.push_back(makeBinaryBlock(TLV_InitialVector,
                                    iv.data(), iv.size()));
  content.encode();
  return content;
}

Buffer
decryptDataContent(const Block& dataBlock,
                   const uint8_t* key, size_t keyLen)
{
  dataBlock.parse();
  Buffer iv(dataBlock.get(TLV_InitialVector).value(),
            dataBlock.get(TLV_InitialVector).value_size());
  Buffer encryptedAesKey(dataBlock.get(TLV_EncryptedAesKey).value(),
                         dataBlock.get(TLV_EncryptedAesKey).value_size());
  Buffer encryptedPayload(dataBlock.get(TLV_EncryptedContent).value(),
                          dataBlock.get(TLV_EncryptedContent).value_size());

  auto aesKey = Rsa::decrypt(key, keyLen, encryptedAesKey.data(), encryptedAesKey.size());
  auto payload = Aes::decrypt(aesKey.data(), aesKey.size(),
                                      encryptedPayload.data(), encryptedPayload.size(), iv);
  return payload;
}

Buffer
decryptDataContent(const Block& dataBlock, const security::Tpm& tpm, const Name& certName)
{
  dataBlock.parse();
  Buffer iv(dataBlock.get(TLV_InitialVector).value(),
            dataBlock.get(TLV_InitialVector).value_size());
  Buffer encryptedAesKey(dataBlock.get(TLV_EncryptedAesKey).value(),
                         dataBlock.get(TLV_EncryptedAesKey).value_size());
  Buffer encryptedPayload(dataBlock.get(TLV_EncryptedContent).value(),
                          dataBlock.get(TLV_EncryptedContent).value_size());

  // auto aesKey = Rsa::decrypt(key, keyLen, encryptedAesKey.data(), encryptedAesKey.size());
  auto aesKey = tpm.decrypt(encryptedAesKey.data(), encryptedAesKey.size(),
                            security::v2::extractKeyNameFromCertName(certName));
  auto payload = Aes::decrypt(aesKey->data(), aesKey->size(),
                              encryptedPayload.data(), encryptedPayload.size(), iv);
  return payload;
}

}
}
