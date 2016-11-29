package org.interledger.cryptoconditions.jce.provider;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Ed25519Fulfillment;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.impl.Ed25519FulfillmentImpl;
import org.interledger.cryptoconditions.oer.OerUtil;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class Ed25519FulfillmentSignatureSpi extends FulfillmentSignatureSpi {

  public Ed25519FulfillmentSignatureSpi() {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-512");
      setInternalSignature(new EdDSAEngine(digest));
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  protected void validatePrivateKey(PrivateKey privateKey) throws InvalidKeyException {

    if (!(privateKey instanceof EdDSAPrivateKey)) {
      throw new InvalidKeyException("Unknown key type used to initiate generation of fulfillment. "
          + "Expecting an EdDSA Private Key");
    }

    EdDSAPrivateKey edDsaPrivateKey = (EdDSAPrivateKey) privateKey;

    if (!edDsaPrivateKey.getParams().getHashAlgorithm().equals("SHA-512"))
      throw new InvalidKeyException("Key hash algorithm must be SHA-512.");

    if (!edDsaPrivateKey.getParams().getCurve().equals(
        EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512).getCurve()))
      throw new InvalidKeyException("Only ED25519 Curve is supported.");
  }


  @Override
  protected void validateSignature(PrivateKey privateKey, byte[] signature)
      throws SignatureException {
    if (signature.length != Ed25519Fulfillment.SIGNATURE_LENGTH)
      throw new SignatureException(
          "Signature size must be " + Ed25519Fulfillment.SIGNATURE_LENGTH + " bytes.");
  }

  @Override
  protected Fulfillment getFulfillment(PrivateKey privateKey, byte[] signature)
      throws SignatureException {

    byte[] a = ((EdDSAPrivateKey) privateKey).getA().toByteArray();

    if (a.length != Ed25519Fulfillment.PUBKEY_LENGTH)
      throw new SignatureException(
          "Invalid key length. " + "Expected " + Ed25519Fulfillment.PUBKEY_LENGTH + " bytes.");

    Ed25519FulfillmentImpl fulfillment = new Ed25519FulfillmentImpl();
    fulfillment.setPublicKey(a);
    fulfillment.setSignature(signature);
    return fulfillment;

  }

  @Override
  protected PublicKey getInternalPublicKey(Fulfillment fulfillment) throws SignatureException {

    try {
      EdDSAPublicKeySpec keySpec =
          new EdDSAPublicKeySpec(((Ed25519Fulfillment) fulfillment).getPublicKey(),
              EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512));
      return new EdDSAPublicKey(keySpec);
    } catch (IllegalArgumentException e) {
      throw new SignatureException("Unable to derive public key from fulfillment.", e);
    }

  }

  @Override
  protected byte[] getInternalSignature(Fulfillment fulfillment) throws SignatureException {
    return ((Ed25519Fulfillment) fulfillment).getSignature();
  }

}
