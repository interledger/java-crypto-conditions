package org.interledger.cryptoconditions;
/**
 * Get the condition for a PREIMAGE-SHA-256 fulfillment
 * 
 * @param fulfillment a PREIMAGE-SHA-256 fulfillment
 *
 * @return the condition that corresponds to the fulfillment
 */

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumSet;

import org.interledger.cryptoconditions.oer.OerUtil;

/**
 * Create a condition from a fulfillment
 * 
 * @author adrianhopebilie
 *
 */
public class ConditionFactory {

  private static MessageDigest _DIGEST = null;


  /**
   * Get the condition for a fulfillment
   * 
   * @param fulfillment a fulfillment of any known type
   *
   * @return the condition that corresponds to the fulfillment
   */
  public static Condition getCondition(Fulfillment fulfillment) {
    switch (fulfillment.getType()) {
      case PREIMAGE_SHA256:
        return getCondition((PreimageSha256Fulfillment) fulfillment);
      case RSA_SHA256:
        return getCondition((RsaSha256Fulfillment) fulfillment);
      case ED25519:
        return getCondition((Ed25519Fulfillment) fulfillment);
      case PREFIX_SHA256:
        return getCondition((PrefixSha256Fulfillment) fulfillment);
      case THRESHOLD_SHA256:
        // TODO: Implement threshold
      default:
        throw new RuntimeException("Unknown fulfillment type.");
    }
  }


  /**
   * Get the condition for a PREIMAGE-SHA-256 fulfillment
   * 
   * @param fulfillment a PREIMAGE-SHA-256 fulfillment
   *
   * @return the condition that corresponds to the fulfillment
   */
  public static Condition getCondition(PreimageSha256Fulfillment fulfillment) {

    byte[] preimage = fulfillment.getPreimage();
    byte[] fingerprint = getDigest(preimage);
    return newCondition(fulfillment, fingerprint);
  }

  /**
   * Get the condition for a RSA-SHA-256 fulfillment
   * 
   * @param fulfillment a RSA-SHA-256 fulfillment
   *
   * @return the condition that corresponds to the fulfillment
   */
  public static Condition getCondition(RsaSha256Fulfillment fulfillment) {

    try {
      byte[] modulus = fulfillment.getModulus().toByteArray();
      byte[] fingerprint = OerUtil.getLengthPrefixedOctetString(modulus);
      return newCondition(fulfillment, fingerprint);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Get the condition for a ED25519 fulfillment
   * 
   * @param fulfillment a ED25519 fulfillment
   *
   * @return the condition that corresponds to the fulfillment
   */
  public static Condition getCondition(Ed25519Fulfillment fulfillment) {

    byte[] fingerprint = fulfillment.getPublicKey();
    return newCondition(fulfillment, fingerprint);
  }

  /**
   * Get the condition for a PREFIX-SHA-256 fulfillment
   * 
   * @param fulfillment a PREFIX-SHA-256 fulfillment
   *
   * @return the condition that corresponds to the fulfillment
   */
  public static Condition getCondition(PrefixSha256Fulfillment fulfillment) {

    try {
      byte[] prefix = OerUtil.getLengthPrefixedOctetString(fulfillment.getPrefix());
      byte[] subcondtion =
          OerUtil.getOerEncodedCondition(getCondition(fulfillment.getSubfulfillment()));

      byte[] fingerprint = Arrays.copyOf(prefix, prefix.length + subcondtion.length);
      System.arraycopy(subcondtion, 0, fingerprint, prefix.length, subcondtion.length);

      return newCondition(fulfillment, fingerprint);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] getDigest(byte[] input) {
    if (_DIGEST == null) {
      try {
        _DIGEST = MessageDigest.getInstance("SHA-256");
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    }

    return _DIGEST.digest(input);
  }

  private static Condition newCondition(Fulfillment fulfillment, byte[] fingerprint) {

    final ConditionType type = fulfillment.getType();
    final int maxFulfillmentLength = fulfillment.getSafeFulfillmentLength();
    final EnumSet<FeatureSuite> features = EnumSet.copyOf(fulfillment.getFeatures());
    final byte[] newFingerprint = fingerprint.clone();

    return new Condition() {
      @Override
      public ConditionType getType() {
        return type;
      }

      @Override
      public int getMaxFulfillmentLength() {
        return maxFulfillmentLength;
      }

      @Override
      public byte[] getFingerprint() {
        return newFingerprint.clone();
      }

      @Override
      public EnumSet<FeatureSuite> getFeatures() {
        return EnumSet.copyOf(features);
      }
    };
  }

}
