package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import org.interledger.cryptoconditions.der.DerEncodingException;
import org.interledger.cryptoconditions.der.DerOutputStream;
import org.interledger.cryptoconditions.der.DerTag;

/**
 * Implements a condition based on a number of subconditions and the SHA-256 function.
 */
public final class ThresholdSha256Condition extends CompoundSha256Condition
    implements CompoundCondition {

  /**
   * Constructs an instance of the condition.
   *
   * @param threshold     The number of subconditions that must be fulfilled.
   * @param subconditions A set of subconditions that this condition is dependent on.
   */
  public ThresholdSha256Condition(final int threshold, final Condition[] subconditions) {
    super(
        hashFingerprintContents(
            constructFingerprintContents(threshold, subconditions)
        ),
        calculateCost(threshold, subconditions),
        calculateSubtypes(subconditions)
    );
  }

  /**
   * Constructs an instance of the condition.
   *
   * Note this constructor is package-private because it is used primarily for testing purposes.
   *
   * @param fingerprint The calculcated fingerprint for the condition.
   * @param cost        The calculated cost of this condition.
   * @param subtypes    A set of condition types for the subconditions that this one depends on.
   */
  ThresholdSha256Condition(byte[] fingerprint, long cost, EnumSet<CryptoConditionType> subtypes) {
    super(fingerprint, cost, subtypes);
  }

  @Override
  public CryptoConditionType getType() {
    return CryptoConditionType.THRESHOLD_SHA256;
  }

  /**
   * Constructs the fingerprint for this condition.
   *
   * Note: This method is package-private as (opposed to private) for testing purposes.
   */
  static final byte[] constructFingerprintContents(
      final int threshold, final Condition[] subconditions
  ) {
    try {

      // Sort
      sortConditions(subconditions);

      // Build subcondition sequence
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      for (int i = 0; i < subconditions.length; i++) {
        out.write(CryptoConditionWriter.writeCondition(subconditions[i]));
      }
      out.close();

      final byte[] subconditionBuffer = baos.toByteArray();

      // Build threshold and subconditions sequence
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeTaggedObject(0, BigInteger.valueOf(threshold).toByteArray());
      out.writeTaggedConstructedObject(1, subconditionBuffer);
      out.close();

      final byte[] thresholdBuffer = baos.toByteArray();

      // Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeEncoded(DerTag.CONSTRUCTED.getTag() + DerTag.SEQUENCE.getTag(), thresholdBuffer);
      out.close();
      return baos.toByteArray();

    } catch (IOException e) {
      throw new UncheckedIOException("DER Encoding Error", e);
    } catch (DerEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Sorts the given array of conditions into ascending lexicographic order.
   *
   * @param conditions The array of conditions to sort.
   */
  private static final void sortConditions(Condition[] conditions) {

    Arrays.sort(conditions, (Comparator<? super Condition>) (Condition c1, Condition c2) -> {
      try {
        byte[] c1encoded = CryptoConditionWriter.writeCondition(c1);
        byte[] c2encoded = CryptoConditionWriter.writeCondition(c2);

        int minLength = Math.min(c1encoded.length, c2encoded.length);
        for (int i = 0; i < minLength; i++) {
          int result = Integer.compareUnsigned(c1encoded[i], c2encoded[i]);
          if (result != 0) {
            return result;
          }
        }
        return c1encoded.length - c2encoded.length;
      } catch (DerEncodingException e) {
        throw new RuntimeException(e);
      }
    });

  }

  /**
   * Calculates the cost of a threshold condition as sum(biggest(t, subcondition_costs)) + 1024 * n
   *
   * @param threshold     The number of subconditions that must be met.
   * @param subconditions The list of subconditions.
   * @return The calculated cost of a threshold condition.
   */
  private static final long calculateCost(int threshold, Condition[] subconditions) {

    // sum(biggest(t, subcondition_costs)) + 1024 * n

    // Sort by cost
    Condition[] sortedConditions = Arrays.copyOf(subconditions, subconditions.length);
    Arrays.sort(sortedConditions, (Comparator<? super Condition>) (Condition c1, Condition c2) -> {
      return (int) (c2.getCost() - c1.getCost());
    });

    long largestCosts = 0;
    for (int i = 0; i < threshold; i++) {
      largestCosts += sortedConditions[i].getCost();
    }

    return largestCosts + (subconditions.length * 1024);
  }

  /**
   * Determines the set of condition types that are ultimately held via the sub condition.
   *
   * @param subconditions The sub conditions that this condition depends on.
   * @return The set of condition types related to the sub condition.
   */
  private static final EnumSet<CryptoConditionType> calculateSubtypes(
      final Condition[] subconditions) {
    // TODO: looks suspiciously similar to the Prefix implementiaton - lets refactor into a common
    // place?
    EnumSet<CryptoConditionType> subtypes = EnumSet.noneOf(CryptoConditionType.class);
    for (int i = 0; i < subconditions.length; i++) {
      subtypes.add(subconditions[i].getType());
      if (subconditions[i] instanceof CompoundCondition) {
        subtypes.addAll(((CompoundCondition) subconditions[i]).getSubtypes());
      }
    }

    // Remove our own type
    if (subtypes.contains(CryptoConditionType.THRESHOLD_SHA256)) {
      subtypes.remove(CryptoConditionType.THRESHOLD_SHA256);
    }

    return subtypes;
  }

}
