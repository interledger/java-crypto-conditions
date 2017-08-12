package org.interledger.cryptoconditions;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Objects;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;


/**
 * An implementation of {@link Fulfillment} for a crypto-condition fulfillment of type
 * "ED25519-SHA256" using the ED-25519 and SHA-256 functions.
 *
 * @see "https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/"
 */
public class Ed25519Sha256Fulfillment implements Fulfillment {

  // Final attributes...
  private final CryptoConditionType type;
  private final EdDSAPublicKey publicKey;
  private final byte[] signature;
  private final Ed25519Sha256Condition condition;

  /**
   * Constructs an instance of the fulfillment.
   *
   * @param publicKey An {@link EdDSAPublicKey} associated with this fulfillment and its
   *                  corresponding condition.
   * @param signature A {@link byte[]} containing the signature associated with this fulfillment.
   */
  public Ed25519Sha256Fulfillment(final EdDSAPublicKey publicKey, final byte[] signature) {
    Objects.requireNonNull(publicKey, "EdDSAPublicKey must not be null!");
    Objects.requireNonNull(signature, "Signature must not be null!");

    this.type = CryptoConditionType.ED25519_SHA256;
    this.publicKey = publicKey;
    this.signature = Arrays.copyOf(signature, signature.length);
    this.condition = new Ed25519Sha256Condition(publicKey);
  }

  @Override
  public CryptoConditionType getType() {
    return this.type;
  }

  /**
   * Returns the public key used.
   */
  public EdDSAPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Returns a copy of the signature linked to this fulfillment.
   */
  public byte[] getSignature() {
    byte[] signature = new byte[this.signature.length];
    System.arraycopy(this.signature, 0, signature, 0, this.signature.length);
    return signature;
  }

  @Override
  public Ed25519Sha256Condition getCondition() {
    return this.condition;
  }

  @Override
  public boolean verify(Condition condition, byte[] message) {

    if (condition == null) {
      throw new IllegalArgumentException(
          "Can't verify a Ed25519Sha256Fulfillment against an null condition.");
    }

    if (!(condition instanceof Ed25519Sha256Condition)) {
      throw new IllegalArgumentException(
          "Must verify a Ed25519Sha256Fulfillment against Ed25519Sha256Condition.");
    }

    if (!getCondition().equals(condition)) {
      return false;
    }

    try {
      // MessageDigest isn't particularly expensive to construct (see MessageDigest source).
      final MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
      final Signature edDsaSigner = new EdDSAEngine(messageDigest);
      edDsaSigner.initVerify(publicKey);
      edDsaSigner.update(message);
      return edDsaSigner.verify(signature);
    } catch (InvalidKeyException | NoSuchAlgorithmException |
        SignatureException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Ed25519Sha256Fulfillment that = (Ed25519Sha256Fulfillment) o;

    if (type != that.type) {
      return false;
    }
    if (!publicKey.equals(that.publicKey)) {
      return false;
    }
    if (!Arrays.equals(signature, that.signature)) {
      return false;
    }
    return condition.equals(that.condition);
  }

  @Override
  public int hashCode() {
    int result = type.hashCode();
    result = 31 * result + publicKey.hashCode();
    result = 31 * result + Arrays.hashCode(signature);
    result = 31 * result + condition.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("Ed25519Sha256Fulfillment{");
    sb.append("type=").append(type);
    sb.append(", publicKey=").append(publicKey);
    sb.append(", signature=").append(Arrays.toString(signature));
    sb.append(", condition=").append(condition);
    sb.append('}');
    return sb.toString();
  }
}
