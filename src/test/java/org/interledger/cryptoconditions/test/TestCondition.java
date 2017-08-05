package org.interledger.cryptoconditions.test;

import org.interledger.cryptoconditions.Condition;

/**
 * An interface (only in existence for testing) that provides access to the unhashed fingerprint of
 * a Condition.
 */
public interface TestCondition extends Condition {

  /**
   *
   * @return
   */
  byte[] getUnhashedFingerprint();

}
