package org.interledger.cryptoconditions.types;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.UnsignedBigInteger;
import org.interledger.cryptoconditions.der.DerOutputStream;

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
  public ConditionType getType() {
    return ConditionType.RSA_SHA256;
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
  public byte[] getEncoded() {
    try {
      // Build preimage sequence
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      out.writeTaggedObject(0, UnsignedBigInteger.toUnsignedByteArray(publicKey.getModulus()));
      out.writeTaggedObject(1, signature);
      out.close();
      byte[] buffer = baos.toByteArray();

      // Wrap CHOICE
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeTaggedConstructedObject(getType().getTypeCode(), buffer);
      out.close();

      return baos.toByteArray();

    } catch (IOException e) {
      throw new UncheckedIOException("DER Encoding Error", e);
    }
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
