package org.interledger.cryptoconditions;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Abstract base class for the *-SHA-256 condition types.
 */
public abstract class Sha256Condition extends ConditionBase {

  private final byte[] fingerprint;
  private final String fingerprintBase64Url;

  /**
   * Constructor that accepts a fingerprint and a cost number.
   *
   * @param cost        A {@link long} representing the anticipated cost of this condition,
   *                    calculated per
   *                    the rules of the crypto-conditions specification.
   * @param fingerprint The binary representation of the fingerprint for this condition.
   */
  protected Sha256Condition(final byte[] fingerprint, final long cost) {
    super(cost);

    Objects.requireNonNull(fingerprint);
    if (fingerprint.length != 32) {
      throw new IllegalArgumentException("Fingerprint must be 32 bytes.");
    }

    Objects.requireNonNull(fingerprint);
    this.fingerprint = Arrays.copyOf(fingerprint, fingerprint.length);
    this.fingerprintBase64Url = Base64.getUrlEncoder().encodeToString(this.fingerprint);
  }

  @Override
  public final byte[] getFingerprint() {
    return fingerprint;
  }

  @Override
  public final String getFingerprintBase64Url() {
    return this.fingerprintBase64Url;
  }

  /**
   * Constructs the fingerprint of this condition by taking the SHA-256 digest of the contents of
   * this condition, per the crypto-conditions RFC.
   *
   * @link fingerprintContents A {@link byte[]} containing the unhashed contents of this condition
   * as assembled per the rules of the RFC.
   */
  protected static final byte[] hashFingerprintContents(final byte[] fingerprintContents) {
    Objects.requireNonNull(fingerprintContents);
    try {
      final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      return messageDigest.digest(fingerprintContents);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
