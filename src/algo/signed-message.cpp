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

#include "signed-message.hpp"
#include <ndn-cxx/util/concepts.hpp>

namespace ndn {
namespace ndnabac {
namespace algo {

template<encoding::Tag TAG>
size_t
SignedMessage::wireEncode(EncodingImpl<TAG>& encoder) const
{
  size_t totalLength = 0;

  // plain text length
  totalLength += prependNonNegativeIntegerBlock(encoder, TLV_PlainTextSize, m_plainTextSize);

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Content);

  return totalLength;
}

template size_t
SignedMessage::wireEncode<encoding::EncoderTag>(EncodingImpl<encoding::EncoderTag>& encoder) const;

template size_t
SignedMessage::wireEncode<encoding::EstimatorTag>(EncodingImpl<encoding::EstimatorTag>& encoder) const;

const Block&
SignedMessage::wireEncode() const
{
  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  this->m_wire = buffer.block();
  return m_wire;
}

void
SignedMessage::wireDecode(const Block& wire)
{
  if (wire.type() != tlv::Content)
    BOOST_THROW_EXCEPTION(tlv::Error("Unexpected TLV type when decoding signed message"));

  this->m_wire = wire;
  m_wire.parse();

  Block::element_const_iterator it = m_wire.elements_begin();

  // plain text length
  if (it != m_wire.elements_end() && it->type() == TLV_PlainTextSize) {
    this->m_plainTextSize = static_cast<uint8_t>(readNonNegativeInteger(*it));
    it++;
  }
  
  // Check if end
  if (it != m_wire.elements_end())
    BOOST_THROW_EXCEPTION(tlv::Error("Unexpected TLV structure after decoding the block"));
}

} // namespace algo
} // namespace ndnabac
} // namespace ndn
