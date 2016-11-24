package org.interledger.cryptoconditions;

/**
 * Enumeration of crypto-condition features
 * 
 * @author adrianhopebailie
 */
public enum FeatureSuite {

  SHA_256(0), PREIMAGE(1), PREFIX(2), THRESHOLD(3), RSA_PSS(4), ED25519(5);

  private final int bitIndex;

  FeatureSuite(int bitIndex) {
    this.bitIndex = bitIndex;
  }

  public int getBitIndex() {
    return this.bitIndex;
  }

}
