package org.interledger.cryptoconditions;

public class PreimageSha256Condition extends Sha256Condition implements SimpleCondition {
  
  private byte[] preimage;
  
  public PreimageSha256Condition(byte[] preimage) {
    super(calculateCost(preimage));
    this.preimage = new byte[preimage.length];
    System.arraycopy(preimage, 0, this.preimage, 0, preimage.length);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.PREIMAGE_SHA256;
  }

  /**
   * The PreimageSha256 fingerprint is the SHA256 hash of the raw preimage
   */
  @Override
  protected byte[] getFingerprintContents() {
    return preimage;
  }
  
  /**
   * cost = length in bytes
   * 
   * @param preimage
   * @return cost
   */
  private static long calculateCost(byte[] preimage) {
    return preimage.length;
  }
}
