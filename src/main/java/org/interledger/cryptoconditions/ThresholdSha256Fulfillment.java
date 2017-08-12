package org.interledger.cryptoconditions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An implementation of {@link Fulfillment} for a crypto-condition fulfillment of type
 * "THRESHOLD-SHA-256" based upon a number of sub-conditions and sub-fulfillments.
 *
 * @see "https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/"
 */
public class ThresholdSha256Fulfillment implements Fulfillment {

  private final CryptoConditionType type;
  // TODO: Remove subconditions as a property...?
  private final List<Condition> subconditions;
  private final List<Fulfillment> subfulfillments;
  private final ThresholdSha256Condition condition;

  /**
   * Required-args Constructor.
   *
   * @param subconditions   An ordered {@link List} of sub-conditions that this
   *                        fulfillment contains.
   * @param subfulfillments An ordered {@link List} of sub-fulfillments that this
   *                        fulfillment contains.
   */
  public ThresholdSha256Fulfillment(
      final List<Condition> subconditions, final List<Fulfillment> subfulfillments
  ) {
    this.type = CryptoConditionType.THRESHOLD_SHA256;
    // Create a new Collections that are unmodifiable so that neither the backing collections
    // nor the actual Collections can be mutated. This works so long as fulfillments are immutable,
    // which they are.
    this.subconditions = Collections.unmodifiableList(new ArrayList<>(subconditions));
    this.subfulfillments = Collections.unmodifiableList(new ArrayList<>(subfulfillments));
    this.condition = this.constructCondition();
  }

  private ThresholdSha256Condition constructCondition() {
    final List<Condition> allConditions = new ArrayList<>();

    // Add all subconditions...
    allConditions.addAll(this.subconditions);

    // Add all derived subconditions...
    allConditions.addAll(
        this.subfulfillments.stream().map(Fulfillment::getCondition).collect(Collectors.toList())
    );

    return new ThresholdSha256Condition(this.subfulfillments.size(), allConditions);
  }

  @Override
  public CryptoConditionType getType() {
    return this.type;
  }

  /**
   * Accessor for the subconditions of this fulfillment.
   *
   * @return An unordered {@link List} of zero or more sub-conditions.
   */
  public final List<Condition> getSubconditions() {
    return this.subconditions;
  }

  /**
   * Accessor for the subfulfillments of this fulfillment.
   *
   * @return An unordered {@link List} of zero or more sub-fulfillments.
   */
  public final List<Fulfillment> getSubfulfillments() {
    return this.subfulfillments;
  }

  @Override
  public ThresholdSha256Condition getCondition() {
    return this.condition;
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

    for (int i = 0; i < subfulfillments.size(); i++) {
      Condition subcondition = subfulfillments.get(i).getCondition();
      if (!subfulfillments.get(i).verify(subcondition, message)) {
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

    if (type != that.type) {
      return false;
    }
    if (!subconditions.equals(that.subconditions)) {
      return false;
    }
    if (!subfulfillments.equals(that.subfulfillments)) {
      return false;
    }
    return condition.equals(that.condition);
  }

  @Override
  public int hashCode() {
    int result = type.hashCode();
    result = 31 * result + subconditions.hashCode();
    result = 31 * result + subfulfillments.hashCode();
    result = 31 * result + condition.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("ThresholdSha256Fulfillment{");
    sb.append("type=").append(type);
    sb.append(", subconditions=").append(subconditions);
    sb.append(", subfulfillments=").append(subfulfillments);
    sb.append(", condition=").append(condition);
    sb.append('}');
    return sb.toString();
  }
}
