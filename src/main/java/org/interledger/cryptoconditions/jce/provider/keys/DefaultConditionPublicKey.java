package org.interledger.cryptoconditions.jce.provider.keys;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.jce.interfaces.ConditionPublicKey;
import org.interledger.cryptoconditions.jce.spec.ConditionKeySpec;
import org.interledger.cryptoconditions.jce.spec.OerEncodedConditionKeySpec;
import org.interledger.cryptoconditions.oer.ConditionOerInputStream;
import org.interledger.cryptoconditions.oer.OerDecodingException;

public class DefaultConditionPublicKey implements ConditionPublicKey {

  private static final long serialVersionUID = 4138666331446619447L;

  // Condition Interface related members
  private final ConditionType type;
  private final EnumSet<FeatureSuite> features;
  private final byte[] fingerprint;
  private final int maxFulfillmentLength;
  private byte[] encoded = null;
  private String format = null;

  private DefaultConditionPublicKey(Condition condition) {

    if (condition.getType() == null)
      throw new IllegalArgumentException("Type cannot be null.");
    byte[] fingerprint = condition.getFingerprint();
    if (fingerprint == null)
      throw new IllegalArgumentException("Fingerprint cannot be null.");

    EnumSet<FeatureSuite> features = condition.getFeatures();
    if (features == null || features.isEmpty())
      throw new IllegalArgumentException("Features cannot be null or empty.");

    if (condition.getMaxFulfillmentLength() < 0)
      throw new IllegalArgumentException("MaxFulfillmentLength can't be negative.");

    this.type = condition.getType();
    this.fingerprint = Arrays.copyOf(fingerprint, fingerprint.length);
    this.features = EnumSet.copyOf(features);
    this.maxFulfillmentLength = condition.getMaxFulfillmentLength();
  }

  public DefaultConditionPublicKey(ConditionKeySpec keySpec) {
    this(keySpec.getCondition());
  }

  public DefaultConditionPublicKey(OerEncodedConditionKeySpec keySpec)
      throws UnsupportedConditionException, OerDecodingException {

    this.encoded = keySpec.getEncoded();
    this.format = "OER";

    ByteArrayInputStream buffer = new ByteArrayInputStream(keySpec.getEncoded());
    ConditionOerInputStream stream = new ConditionOerInputStream(buffer);

    try {
      Condition condition = stream.readCondition();
      this.type = condition.getType();
      this.fingerprint = condition.getFingerprint();
      this.features = condition.getFeatures();
      this.maxFulfillmentLength = condition.getMaxFulfillmentLength();
    } catch (IOException e) {
      throw new RuntimeException(e);
    } finally {
      try {
        stream.close();
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

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

  @Override
  public String getAlgorithm() {
    return "CryptoConditions";
  }

  @Override
  public String getFormat() {
    return this.format;
  }

  @Override
  public byte[] getEncoded() {
    if (encoded != null)
      return encoded.clone();

    return null;
  }

}
