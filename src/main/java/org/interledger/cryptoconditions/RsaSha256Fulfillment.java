package org.interledger.cryptoconditions;

import static org.interledger.cryptoconditions.CryptoConditionType.RSA_SHA256;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * An implementation of {@link Fulfillment} for a crypto-condition fulfillment of type
 * "RSA-SHA-256" based upon an RSA key and the SHA-256 function.
 *
 * @see "https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/"
 */
public class RsaSha256Fulfillment extends FulfillmentBase<RsaSha256Condition>
    implements Fulfillment<RsaSha256Condition> {

  public static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
  public static final String SHA_256_WITH_RSA_PSS = "SHA256withRSA/PSS";

  private final RSAPublicKey publicKey;
  private final byte[] signature;
  private final RsaSha256Condition condition;

  /**
   * Constructs an instance of the fulfillment.
   *
   * @param publicKey An {@link RSAPublicKey} to be used with this fulfillment.
   * @param signature A {@link byte[]} that contains a binary representation of the signature
   *                  associated with this fulfillment.
   */
  public RsaSha256Fulfillment(final RSAPublicKey publicKey, final byte[] signature) {
    super(RSA_SHA256);
    Objects.requireNonNull(publicKey, "PublicKey must not be null!");
    Objects.requireNonNull(signature, "Signature must not be null!");

    this.publicKey = publicKey;
    this.signature = Arrays.copyOf(signature, signature.length);
    this.condition = new RsaSha256Condition(publicKey);
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
    return this.condition;
  }

  @Override
  public boolean verify(final RsaSha256Condition condition, final byte[] message) {
    Objects.requireNonNull(condition,
        "Can't verify a RsaSha256Fulfillment against an null condition.");
    Objects.requireNonNull(message, "Message must not be null!");

    if (!getCondition().equals(condition)) {
      return false;
    }

    try {
      Signature rsaSigner = Signature.getInstance(SHA_256_WITH_RSA_PSS);
      rsaSigner.initVerify(publicKey);
      rsaSigner.update(message);
      return rsaSigner.verify(signature);
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
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
    if (!super.equals(o)) {
      return false;
    }

    RsaSha256Fulfillment that = (RsaSha256Fulfillment) o;

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
    int result = super.hashCode();
    result = 31 * result + publicKey.hashCode();
    result = 31 * result + Arrays.hashCode(signature);
    result = 31 * result + condition.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("RsaSha256Fulfillment{");
    sb.append("publicKey=").append(publicKey);
    sb.append(", signature=").append(Arrays.toString(signature));
    sb.append(", condition=").append(condition);
    sb.append(", type=").append(getType());
    sb.append('}');
    return sb.toString();
  }
}
