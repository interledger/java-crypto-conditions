package org.interledger.cryptoconditions.jce.spec;

import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;

/**
 * This class represents the ASN.1 encoding of a public key, encoded according to the ASN.1 type
 * {@code Condition} using OER encoding rules.
 * 
 * The {@code Condition} syntax is defined in the Crypto-Conditions standard as follows:
 *
 * <pre>
 * Condition ::= SEQUENCE {
 *     type ConditionType,
 *     featureBitmask OCTET STRING,
 *     fingerprint OCTET STRING,
 *     maxFulfillmentLength INTEGER (0..MAX)
 * }
 * 
 * ConditionType ::= INTEGER {
 *     preimageSha256(0),
 *     rsaSha256(1),
 *     prefixSha256(2),
 *     thresholdSha256(3),
 *     ed25519(4)
 * } (0..65535)
 * </pre>
 *
 * @author Adrian Hope-Bailie <adrian@hopebailie.com>
 *
 *
 * @see java.security.Key
 * @see java.security.KeyFactory
 * @see KeySpec
 * @see EncodedKeySpec
 * @see org.interledger.cryptoconditions.Condition
 */
public class OerEncodedConditionKeySpec extends EncodedKeySpec {


  public OerEncodedConditionKeySpec(byte[] oerEncodedCondition) {
    super(oerEncodedCondition);
  }

  @Override
  public String getFormat() {
    return "OER";
  }

}
