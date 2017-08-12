package org.interledger.cryptoconditions;

import java.util.EnumSet;
import java.util.Objects;

/**
 * An abstract implementation of {@link CompoundCondition} that extends {@link Sha256Condition} to
 * provide common functionality for all compound condition classes.
 */
public abstract class CompoundSha256Condition extends Sha256Condition implements CompoundCondition {

  private final EnumSet<CryptoConditionType> subtypes;

  /**
   * Constructor that accepts a fingerprint and a cost number.
   *
   * @param cost        A {@link long} representing the anticipated cost of this condition,
   *                    calculated per
   *                    the rules of the crypto-conditions specification.
   * @param fingerprint The binary representation of the fingerprint for this condition.
   * @param subtypes    A {@link EnumSet} of the sub-types of this compound condition.
   */
  protected CompoundSha256Condition(
      final byte[] fingerprint, final long cost, final EnumSet<CryptoConditionType> subtypes
  ) {
    super(fingerprint, cost);
    this.subtypes = EnumSet.copyOf(Objects.requireNonNull(subtypes));
  }

  @Override
  public final EnumSet<CryptoConditionType> getSubtypes() {
    return EnumSet.copyOf(subtypes);
  }

}
