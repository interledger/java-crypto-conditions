package org.interledger.cryptoconditions;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Implementation of a fulfillment based on an RSA key and the SHA-256 function.
 */
public class RsaSha256Fulfillment implements Fulfillment {

  public static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);

  private RsaSha256Condition condition;
  private RSAPublicKey publicKey;
  private byte[] signature;

  /**
   * Constructs an instance of the fulfillment.
   *
   * @param publicKey The public key used with the fulfillment.
   * @param signature The signature used with the fulfillment.
   */
  public RsaSha256Fulfillment(RSAPublicKey publicKey, byte[] signature) {
    this.signature = new byte[signature.length];
    System.arraycopy(signature, 0, this.signature, 0, signature.length);
    this.publicKey = publicKey;
  }

  @Override
  public CryptoConditionType getType() {
    return CryptoConditionType.RSA_SHA256;
  }

  /**
   * Returns the public key used in this fulfillment.
   */
  public RSAPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Returns a copy of the signature used in this fulfillment.
   */
  public byte[] getSignature() {
    byte[] signature = new byte[this.signature.length];
    System.arraycopy(this.signature, 0, signature, 0, this.signature.length);
    return signature;
  }

  @Override
  public RsaSha256Condition getCondition() {
    if (condition == null) {
      condition = new RsaSha256Condition(publicKey);
    }
    return condition;
  }

  @Override
  public boolean verify(Condition condition, byte[] message) {

    if (condition == null) {
      throw new IllegalArgumentException(
          "Can't verify a RsaSha256Fulfillment against an null condition.");
    }

    if (!(condition instanceof RsaSha256Condition)) {
      throw new IllegalArgumentException(
          "Must verify a RsaSha256Fulfillment against RsaSha256Condition.");
    }

    if (!getCondition().equals(condition)) {
      return false;
    }

    try {
      Signature rsaSigner = Signature.getInstance("SHA256withRSA/PSS");
      rsaSigner.initVerify(publicKey);
      rsaSigner.update(message);
      return rsaSigner.verify(signature);
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new RuntimeException(e);
    }

  }

  /**
   * The {@link #condition} field in this class is not part of this equals method because it is a
   * value derived from this fulfillment, and is lazily initialized (so it's occasionally null until
   * {@link #getCondition()} is called.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    RsaSha256Fulfillment that = (RsaSha256Fulfillment) o;

    if (!publicKey.equals(that.publicKey)) {
      return false;
    }
    return Arrays.equals(signature, that.signature);
  }

  @Override
  public int hashCode() {
    int result = publicKey.hashCode();
    result = 31 * result + Arrays.hashCode(signature);
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("RsaSha256Fulfillment{");
    sb.append("publicKey=").append(publicKey);
    sb.append(", type=").append(getType());
    sb.append('}');
    return sb.toString();
  }
}
