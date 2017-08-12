package org.interledger.cryptoconditions;

import java.util.Base64;

/**
 * An implementation of {@link Fulfillment} for a crypto-condition fulfillment of type
 * "PREIMAGE-SHA-256" based upon a preimage and the SHA-256 hash function.
 *
 * @see "https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/"
 */
public class PreimageSha256Fulfillment implements Fulfillment<PreimageSha256Condition> {

  private final CryptoConditionType type;
  private final PreimageSha256Condition condition;
  private final String base64UrlEncodedPreimage;

  /**
   * Constructs an instance of the fulfillment.
   *
   * @param preimage The preimage associated with the fulfillment.
   */
  public PreimageSha256Fulfillment(byte[] preimage) {
    this.type = CryptoConditionType.PREIMAGE_SHA256;
    this.condition = new PreimageSha256Condition(preimage);
    this.base64UrlEncodedPreimage = Base64.getUrlEncoder().encodeToString(preimage);
  }

  @Override
  public CryptoConditionType getType() {
    return type;
  }

  @Override
  public PreimageSha256Condition getCondition() {
    return this.condition;
  }

  public String getBase64UrlEncodedPreimage() {
    return this.base64UrlEncodedPreimage;
  }

  @Override
  public boolean verify(final PreimageSha256Condition condition, final byte[] message) {

    if (condition == null) {
      throw new IllegalArgumentException(
          "Can't verify a PreimageSha256Fulfillment against an null condition.");
    }

    if (!(condition instanceof PreimageSha256Condition)) {
      throw new IllegalArgumentException(
          "Must verify a PreimageSha256Fulfillment against PreimageSha256Condition.");
    }

    return getCondition().equals(condition);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    PreimageSha256Fulfillment that = (PreimageSha256Fulfillment) o;

    if (type != that.type) {
      return false;
    }
    if (!condition.equals(that.condition)) {
      return false;
    }
    return base64UrlEncodedPreimage.equals(that.base64UrlEncodedPreimage);
  }

  @Override
  public int hashCode() {
    int result = type.hashCode();
    result = 31 * result + condition.hashCode();
    result = 31 * result + base64UrlEncodedPreimage.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("PreimageSha256Fulfillment{");
    sb.append("type=").append(type);
    sb.append(", condition=").append(condition);
    sb.append(", base64UrlEncodedPreimage='").append(base64UrlEncodedPreimage).append('\'');
    sb.append('}');
    return sb.toString();
  }
}
