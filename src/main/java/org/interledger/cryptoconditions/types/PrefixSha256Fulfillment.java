package org.interledger.cryptoconditions.types;

import java.util.Arrays;
import java.util.Objects;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;

/**
 * Implementation of a fulfillment based on a prefix, a sub fulfillment, and the SHA-256 function.
 */
public class PrefixSha256Fulfillment implements Fulfillment {

  private PrefixSha256Condition condition;
  private Fulfillment subfulfillment;

  private long maxMessageLength;
  private byte[] prefix;

  /**
   * Constructs an instance of the fulfillment.
   *
   * @param prefix           The prefix associated with the condition and fulfillment
   * @param maxMessageLength The maximum length of a message.
   * @param subfulfillment   The sub fulfillments that this fulfillment depends on.
   */
  public PrefixSha256Fulfillment(byte[] prefix, long maxMessageLength, Fulfillment subfulfillment) {
    this.prefix = new byte[prefix.length];
    System.arraycopy(prefix, 0, this.prefix, 0, prefix.length);

    this.maxMessageLength = maxMessageLength;

    // FIXME Safe copy?
    this.subfulfillment = subfulfillment;
  }

  @Override
  public ConditionType getType() {
    return ConditionType.PREFIX_SHA256;
  }

  /**
   * Returns a copy of the prefix used in this fulfillment.
   */
  public byte[] getPrefix() {
    byte[] prefix = new byte[this.prefix.length];
    System.arraycopy(this.prefix, 0, prefix, 0, this.prefix.length);
    return prefix;
  }

  /**
   * Returns the maximum allowable message length.
   */
  public long getMaxMessageLength() {
    return maxMessageLength;
  }

  /**
   * Returns the sub fulfillment that this fulfillment depends on.
   */
  public Fulfillment getSubfulfillment() {
    return subfulfillment;
  }

  @Override
  public PrefixSha256Condition getCondition() {
    if (condition == null) {
      condition =
          new PrefixSha256Condition(prefix, maxMessageLength, subfulfillment.getCondition());
    }
    return condition;
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

    Condition subcondition = subfulfillment.getCondition();
    byte[] prefixedMessage = Arrays.copyOf(prefix, prefix.length + message.length);
    System.arraycopy(message, 0, prefixedMessage, prefix.length, message.length);

    return subfulfillment.verify(subcondition, prefixedMessage);
  }

  /**
   * The {@link #condition} field in this class is not part of this equals method because it is a
   * value derived from this fulfillment, and is lazily initialized (so it's occasionally null until
   * {@link #getCondition()} is called.
   */
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
    if (subfulfillment != null ? !subfulfillment.equals(that.subfulfillment)
        : that.subfulfillment != null) {
      return false;
    }
    return Arrays.equals(prefix, that.prefix);
  }

  @Override
  public int hashCode() {
    int result = subfulfillment != null ? subfulfillment.hashCode() : 0;
    result = 31 * result + (int) (maxMessageLength ^ (maxMessageLength >>> 32));
    result = 31 * result + Arrays.hashCode(prefix);
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("PrefixSha256Fulfillment{");
    sb.append("maxMessageLength=").append(maxMessageLength);
    sb.append(", prefix=").append(Arrays.toString(prefix));
    sb.append(", type=").append(getType());
    sb.append('}');
    return sb.toString();
  }
}
