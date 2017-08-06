package org.interledger.cryptoconditions.types;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Objects;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Sha256Condition;
import org.interledger.cryptoconditions.SimpleCondition;
import org.interledger.cryptoconditions.der.DerOutputStream;
import org.interledger.cryptoconditions.der.DerTag;

/**
 * Implementation of a crypto-condition using the ED-25519 and SHA-256 functions.
 */
public final class Ed25519Sha256Condition extends Sha256Condition implements SimpleCondition {

  /**
   * Constructs an instance of the condition.
   *
   * @param key A {@link EdDSAPublicKey} used to create the fingerprint.
   */
  public Ed25519Sha256Condition(final EdDSAPublicKey key) {
    super(
        hashFingerprintContents(
            constructFingerprintContents(key)
        ),
        calculateCost(key));
  }

  /**
   * Constructs an instance of the condition with the given fingerprint and cost.
   *
   * @param fingerprint The fingerprint associated with the condition.
   * @param cost        The cost associated with the condition.
   */
  Ed25519Sha256Condition(byte[] fingerprint, long cost) {
    super(fingerprint, cost);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.ED25519_SHA256;
  }

  /**
   * Construct the fingerprint contents for this condition.
   *
   * @param publicKey
   * @return
   */
  final static byte[] constructFingerprintContents(final EdDSAPublicKey publicKey) {

    Objects.requireNonNull(publicKey);
    validatePublicKey(publicKey);

    try {
      // Write public publicKey
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      out.writeTaggedObject(0, publicKey.getA().toByteArray());
      out.close();
      byte[] buffer = baos.toByteArray();

      // Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeEncoded(DerTag.CONSTRUCTED.getTag() + DerTag.SEQUENCE.getTag(), buffer);
      out.close();

      return baos.toByteArray();

    } catch (IOException ioe) {
      throw new UncheckedIOException("DER Encoding Error", ioe);
    }
  }

  /**
   * Returns the cost of the condition (131072).
   *
   * @param key the key used in the condition.
   * @return the cost of the condition
   */
  private static long calculateCost(final EdDSAPublicKey key) {
    return 131072; //TODO: is this a placehoder, or should it be a constant?
  }

  private static final void validatePublicKey(final EdDSAPublicKey publicKey) {
    // TODO: Validate key?
  }
}
