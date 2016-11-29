package org.interledger.cryptoconditions.jce.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.EnumSet;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.impl.RsaSha256FulfillmentImpl;
import org.interledger.cryptoconditions.oer.OerUtil;
import org.interledger.cryptoconditions.util.UnsignedBigInteger;

public class RsaSha256FulfillmentSignatureSpi extends FulfillmentSignatureSpi {

  private static final PSSParameterSpec RSASSA_PSS_SIGNATURE_PARAMETERS =
      new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);

  public RsaSha256FulfillmentSignatureSpi() {
    try {
      Signature signature = Signature.getInstance("SHA256withRSA/PSS");
      signature.setParameter(RSASSA_PSS_SIGNATURE_PARAMETERS);
      setInternalSignature(signature);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  protected void validatePrivateKey(PrivateKey privateKey) throws InvalidKeyException {

    if (!(privateKey instanceof RSAPrivateKey)) {
      throw new InvalidKeyException("Unknown key type used to initiate generation of fulfillment. "
          + "Expecting an RSA Private Key");
    }

    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
    byte[] modulus = rsaPrivateKey.getModulus().toByteArray();

    if (modulus.length < RsaSha256Fulfillment.MINIMUM_MODULUS_SIZE)
      throw new InvalidKeyException("Modulus size cannot be smaller than "
          + RsaSha256Fulfillment.MINIMUM_MODULUS_SIZE + " bytes.");

    if (modulus.length > RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE)
      throw new InvalidKeyException("Modulus size cannot be larger than "
          + RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE + " bytes.");

    if (!isValidRsaKeyPair(rsaPrivateKey.getPrivateExponent(),
        RsaSha256Fulfillment.RSA_PUBLIC_EXPONENT, rsaPrivateKey.getModulus())) {
      throw new InvalidKeyException("Modulus size cannot be larger than "
          + RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE + " bytes.");
    }

  }

  @Override
  protected void validateSignature(PrivateKey privateKey, byte[] signature)
      throws SignatureException {
    if (signature.length < RsaSha256Fulfillment.MINIMUM_SIGNATURE_SIZE)
      throw new SignatureException("Signature size cannot be smaller than "
          + RsaSha256Fulfillment.MINIMUM_SIGNATURE_SIZE + " bytes.");

    if (signature.length > RsaSha256Fulfillment.MAXIMUM_SIGNATURE_SIZE)
      throw new SignatureException("Signature size cannot be larger than "
          + RsaSha256Fulfillment.MAXIMUM_SIGNATURE_SIZE + " bytes.");

    byte[] modulus =
        UnsignedBigInteger.toUnsignedByteArray(((RSAPrivateKey) privateKey).getModulus());

    if (signature.length != modulus.length)
      throw new SignatureException("Modulus and signature must be the same size.");

    if (((RSAPrivateKey) privateKey).getModulus().compareTo(new BigInteger(signature)) <= 0)
      throw new SignatureException("Signature must be numerically smaller than modulus.");
  }

  @Override
  protected Fulfillment getFulfillment(PrivateKey privateKey, byte[] signature)
      throws SignatureException {

    RsaSha256FulfillmentImpl fulfillment = new RsaSha256FulfillmentImpl();
    fulfillment.setModulus(((RSAPrivateKey) privateKey).getModulus());
    fulfillment.setSignature(signature);
    return fulfillment;

  }

  @Override
  protected PublicKey getInternalPublicKey(Fulfillment fulfillment) throws SignatureException {

    RSAPublicKeySpec keySpec =
        new RSAPublicKeySpec(((RsaSha256Fulfillment) fulfillment).getModulus(),
            RsaSha256Fulfillment.RSA_PUBLIC_EXPONENT);

    try {
      KeyFactory factory = KeyFactory.getInstance("RSA");
      return factory.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException e) {
      throw new SignatureException(e);
    } catch (InvalidKeySpecException e) {
      throw new SignatureException(e);
    }

  }

  @Override
  protected byte[] getInternalSignature(Fulfillment fulfillment) throws SignatureException {
    return ((RsaSha256Fulfillment) fulfillment).getSignature();
  }

  private boolean isValidRsaKeyPair(BigInteger privExponent, BigInteger pubExponent,
      BigInteger sharedModulus) {

    BigInteger calc = BigInteger.valueOf(2)
        .modPow((pubExponent.multiply(privExponent)).subtract(BigInteger.ONE), sharedModulus);

    return BigInteger.ONE.equals(calc);
  }

}
