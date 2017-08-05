package org.interledger.cryptoconditions;

import java.net.URI;

/**
 * Java implementation of Crypto-Conditions Condition.
 *
 * @author adrianhopebailie
 * @see<a href="https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/">
 * https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/</a>
 */
public interface Condition {

  /**
   * The type identifier representing the condition type.
   *
   * @return the type of this condition
   */
  ConditionType getType();

  /**
   * <p>A fingerprint is a binary (aka "octet") string uniquely representing the condition with
   * respect to other conditions of the same type. Implementations which index conditions MUST use
   * the entire string or binary encoded condition as the key - not just the fingerprint - as
   * different conditions of different types may have the same fingerprint.</p>
   * <p>
   * The length and contents of the fingerprint are defined by the condition type. The fingerprint
   * is a cryptographically secure hash of the data which defines the condition, such as a public
   * key.</p>
   *
   * @return the unique fingerprint of this condition
   */
  byte[] getFingerprint();

  /**
   * The estimated "cost" of processing a fulfillment of this condition. For details of how to
   * calculate this number see the Crypto-conditions specification.
   *
   * @return the cost of validating the fulfillment of this condition
   */
  long getCost();

  /**
   * Get the condition encoded in ASN.1 DER binary encoding.
   *
   * @return the DER encoded condition
   */
  byte[] getEncoded();

  /**
   * Get the Named Information URL that describes this condition.
   *
   * @return an ni:// URI that identifes this condition
   */
  URI getUri();
}
