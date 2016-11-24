package org.interledger.cryptoconditions.impl;

import java.util.Arrays;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.oer.OerUtil;

/**
 * Convenience class used to generate a new immutable condition object
 * 
 * @author adrianhopebailie
 */
public class ConditionImpl implements Condition {

  // Condition Interface related members
  private final ConditionType type;
  private final EnumSet<FeatureSuite> features;
  private final byte[] fingerprint;
  private final int maxFulfillmentLength;

  public ConditionImpl(ConditionType type, EnumSet<FeatureSuite> features, byte[] fingerprint,
      int maxFulfillmentLength) {

    if (type == null)
      throw new IllegalArgumentException("Type cannot be null.");

    if (fingerprint == null)
      throw new IllegalArgumentException("Fingerprint cannot be null.");

    if (features == null || features.isEmpty())
      throw new IllegalArgumentException("Features cannot be null or empty.");

    if (maxFulfillmentLength < 0)
      throw new IllegalArgumentException("MaxFulfillmentLength can't be negative.");

    if (maxFulfillmentLength > OerUtil.MAX_INT)
      throw new IllegalArgumentException(
          "MaxFulfillmentLength greater than " + OerUtil.MAX_INT + " are not supported.");

    this.type = type;
    this.fingerprint = Arrays.copyOf(fingerprint, fingerprint.length);
    this.features = EnumSet.copyOf(features);
    this.maxFulfillmentLength = maxFulfillmentLength;
  }

  @Override
  public ConditionType getType() {
    return this.type;
  }

  @Override
  public EnumSet<FeatureSuite> getFeatures() {
    return EnumSet.copyOf(this.features);
  }


  @Override
  public byte[] getFingerprint() {
    return Arrays.copyOf(this.fingerprint, this.fingerprint.length);
  }

  @Override
  public int getMaxFulfillmentLength() {
    return this.maxFulfillmentLength;
  }

}
