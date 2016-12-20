package org.interledger.cryptoconditions;

import java.net.URI;

/**
 * Crypto-conditions are distributable event descriptions. This means crypto-conditions say how to
 * recognize a message without saying exactly what the message is. You can transmit a
 * crypto-condition freely, but you cannot forge the message it describes.
 * 
 * <p>
 * For convenience, we hash the description so that the crypto-condition can be a fixed size.
 * 
 * @author adrianhopebailie
 *
 */
public interface Condition {

  /**
   * The numeric type identifier representing the condition type.
   * 
   * @return the type of this condition
   */
  ConditionType getType();

  /**
   * A binary string uniquely representing the condition with respect to other conditions of the
   * same type. Implementations which index conditions MUST use the entire string or binary encoded
   * condition as the key, not just the fingerprint - as different conditions of different types may
   * have the same fingerprint.
   * 
   * <p>
   * The length and contents of the fingerprint are defined by the condition type. For most
   * condition types, the fingerprint is a cryptographically secure hash of the data which defines
   * the condition, such as a public key.
   * 
   * @return the unique fingerprint of this condition
   */
  byte[] getFingerprint();

  /**
   * The maximum length of the fulfillment payload that can fulfill this condition, in bytes. The
   * payload size is measured unencoded. (The size of the payload is larger in BASE64URL format.)
   * 
   * <p>
   * When a crypto-condition is submitted to an implementation, this implementation MUST verify that
   * it will be able to process a fulfillment with a payload of size maxFulfillmentLength.
   * 
   * @return the maximum length (in bytes) of this condition's fulfillment
   */
  long getCost();
  
  byte[] getEncoded();
  
  URI getURI();

}
