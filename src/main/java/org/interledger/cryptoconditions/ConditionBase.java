package org.interledger.cryptoconditions;

/**
 * This class provides shared, concrete logic for all conditions.
 */
public abstract class ConditionBase implements Condition {

  private final long cost;

  /**
   * Default internal constructor for all conditions. Sub-classes must statically calculate the cost
   * of a condition and call this constructor with the correct cost value.
   *
   * @param cost the cost value for this condition.
   */
  protected ConditionBase(final long cost) {
    if (cost < 0) {
      throw new IllegalArgumentException("Cost must be positive!");
    }

    this.cost = cost;
  }

  @Override
  public final long getCost() {
    return cost;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    ConditionBase that = (ConditionBase) o;

    return cost == that.cost;
  }

  @Override
  public int hashCode() {
    return (int) (cost ^ (cost >>> 32));
  }

  /**
   * Overrides the default {@link java.lang.Object#toString()} and returns the result of
   * {@link CryptoConditionUri#toUri(Condition)} as a string.
   */
  @Override
  public final String toString() {
    return CryptoConditionUri.toUri(this).toString();
  }

}
