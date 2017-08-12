package org.interledger.cryptoconditions;

import java.util.Arrays;
import java.util.Objects;

/**
 * Implementation of a fulfillment based on a prefix, a sub fulfillment, and the SHA-256 function.
 */
public class PrefixSha256Fulfillment implements Fulfillment {

  private final CryptoConditionType type;
  private final byte[] prefix;
  private final long maxMessageLength;
  private final Fulfillment subfulfillment;
  private final PrefixSha256Condition condition;

  /**
   * Constructs an instance of the fulfillment.
   *
   * @param prefix           The prefix associated with the condition and fulfillment
   * @param maxMessageLength The maximum length of a message.
   * @param subfulfillment   The subfulfillments that this fulfillment depends on.
   */
  public PrefixSha256Fulfillment(
      final byte[] prefix, final long maxMessageLength, final Fulfillment subfulfillment
  ) {
    Objects.requireNonNull(prefix, "Prefix must not be null!");
    Objects.requireNonNull(subfulfillment, "Subfulfillment must not be null!");

    this.type = CryptoConditionType.PREFIX_SHA256;
    this.prefix = Arrays.copyOf(prefix, prefix.length);
    this.maxMessageLength = maxMessageLength;
    // Fulfillments are immutable, so no need to perform any type of deep-copy here.
    this.subfulfillment = subfulfillment;

    this.condition = new PrefixSha256Condition(prefix, maxMessageLength,
        subfulfillment.getCondition());
  }

  @Override
  public CryptoConditionType getType() {
    return type;
  }

  @Override
  public final PrefixSha256Condition getCondition() {
    return this.condition;
  }

  public byte[] getPrefix() {
    return prefix;
  }

  public long getMaxMessageLength() {
    return maxMessageLength;
  }

  public Fulfillment getSubfulfillment() {
    return subfulfillment;
  }

  @Override
  public boolean verify(final Condition condition, final byte[] message) {
    Objects.requireNonNull(condition,
        "Can't verify a PrefixSha256Fulfillment against a null condition!");

    if (!(condition instanceof PrefixSha256Condition)) {
      throw new IllegalArgumentException(
          "Must verify a PrefixSha256Fulfillment against PrefixSha256Condition.");
    }

    if (message.length > maxMessageLength) {
      throw new IllegalArgumentException(
          String
              .format("Message length (%s) exceeds maximum message length of (%s).", message.length,
                  maxMessageLength));
    }

    if (!getCondition().equals(condition)) {
      return false;
    }

    final Condition subcondition = subfulfillment.getCondition();
    final byte[] prefixedMessage = Arrays.copyOf(prefix, prefix.length + message.length);
    System.arraycopy(message, 0, prefixedMessage, prefix.length, message.length);

    return subfulfillment.verify(subcondition, prefixedMessage);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    PrefixSha256Fulfillment that = (PrefixSha256Fulfillment) o;

    if (maxMessageLength != that.maxMessageLength) {
      return false;
    }
    if (type != that.type) {
      return false;
    }
    if (!Arrays.equals(prefix, that.prefix)) {
      return false;
    }
    if (!subfulfillment.equals(that.subfulfillment)) {
      return false;
    }
    return condition.equals(that.condition);
  }

  @Override
  public int hashCode() {
    int result = type.hashCode();
    result = 31 * result + Arrays.hashCode(prefix);
    result = 31 * result + (int) (maxMessageLength ^ (maxMessageLength >>> 32));
    result = 31 * result + subfulfillment.hashCode();
    result = 31 * result + condition.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("PrefixSha256Fulfillment{");
    sb.append("type=").append(type);
    sb.append(", prefix=").append(Arrays.toString(prefix));
    sb.append(", maxMessageLength=").append(maxMessageLength);
//    sb.append(", subfulfillment=").append(subfulfillment);
    sb.append(", condition=").append(condition);
    sb.append('}');
    return sb.toString();
  }

}
