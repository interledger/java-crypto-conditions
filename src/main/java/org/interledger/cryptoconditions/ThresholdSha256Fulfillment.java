package org.interledger.cryptoconditions;

import java.util.Arrays;

/**
 * Implementation of a fulfillment based on a number of subconditions and subfulfillments.
 */
public class ThresholdSha256Fulfillment implements Fulfillment {

  private ThresholdSha256Condition condition;
  // TODO: Remove subconditions as a property...?
  private Condition[] subconditions;
  private Fulfillment[] subfulfillments;

  /**
   * Constructs an instance of the fulfillment.
   *
   * @param subconditions   A set of conditions that this fulfillment relates to.
   * @param subfulfillments A set of subfulfillments this fulfillment relates to.
   */
  public ThresholdSha256Fulfillment(
      final Condition[] subconditions, final Fulfillment[] subfulfillments
  ) {
    this.subconditions = new Condition[subconditions.length];
    System.arraycopy(subconditions, 0, this.subconditions, 0, subconditions.length);

    // TODO Clone each fulfillment?
    this.subfulfillments = new Fulfillment[subfulfillments.length];
    System.arraycopy(subfulfillments, 0, this.subfulfillments, 0, subfulfillments.length);
  }

  @Override
  public CryptoConditionType getType() {
    return CryptoConditionType.THRESHOLD_SHA256;
  }

  public int getThreshold() {
    return subfulfillments.length;
  }

  /**
   * Returns a copy of the subconditions linked to this fulfillment.
   */
  public Condition[] getSubconditions() {
    Condition[] subconditions = new Condition[this.subconditions.length];
    System.arraycopy(this.subconditions, 0, subconditions, 0, this.subconditions.length);
    return subconditions;
  }

  /**
   * Returns a copy of the subfulfillments linked to this fulfillment.
   */
  public Fulfillment[] getSubfulfillments() {
    Fulfillment[] subfulfillments = new Fulfillment[this.subfulfillments.length];
    System.arraycopy(this.subfulfillments, 0, subfulfillments, 0, this.subfulfillments.length);
    return subfulfillments;
  }

  @Override
  public ThresholdSha256Condition getCondition() {
    if (condition == null) {

      // Copy all subconditions into another array along with the conditions *derived* from all
      // subfulfillments
      Condition[] allConditions = new Condition[subconditions.length + subfulfillments.length];
      System.arraycopy(subconditions, 0, allConditions, 0, subconditions.length);
      int idx = subconditions.length;
      for (int i = 0; i < subfulfillments.length; i++) {
        allConditions[idx] = subfulfillments[i].getCondition();
        idx++;
      }
      condition = new ThresholdSha256Condition(subfulfillments.length, allConditions);
    }
    return condition;
  }

  @Override
  public boolean verify(Condition condition, byte[] message) {

    if (condition == null) {
      throw new IllegalArgumentException(
          "Can't verify a ThresholdSha256Fulfillment against an null condition.");
    }

    if (!(condition instanceof ThresholdSha256Condition)) {
      throw new IllegalArgumentException(
          "Must verify a ThresholdSha256Fulfillment against ThresholdSha256Condition.");
    }

    if (!getCondition().equals(condition)) {
      return false;
    }

    for (int i = 0; i < subfulfillments.length; i++) {
      Condition subcondition = subfulfillments[i].getCondition();
      if (!subfulfillments[i].verify(subcondition, message)) {
        return false;
      }
    }

    return true;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    ThresholdSha256Fulfillment that = (ThresholdSha256Fulfillment) o;

    // Probably incorrect - comparing Object[] arrays with Arrays.equals
    return Arrays.equals(subfulfillments, that.subfulfillments);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(subfulfillments);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("ThresholdSha256Fulfillment{");
    sb.append("type=").append(getType());
    sb.append(", threshold=").append(getThreshold());
    sb.append('}');
    return sb.toString();
  }
}
