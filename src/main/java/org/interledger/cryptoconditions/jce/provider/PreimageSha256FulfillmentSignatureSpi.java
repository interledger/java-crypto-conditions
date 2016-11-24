package org.interledger.cryptoconditions.jce.provider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.impl.PreimageSha256FulfillmentImpl;
import org.interledger.cryptoconditions.jce.provider.keys.Sha256DigestPrivateKey;
import org.interledger.cryptoconditions.jce.provider.keys.Sha256DigestPublicKey;
import org.interledger.cryptoconditions.oer.OerUtil;

public class PreimageSha256FulfillmentSignatureSpi extends FulfillmentSignatureSpi {

  public PreimageSha256FulfillmentSignatureSpi() {
    try {
      setInternalSignature(getSha256DigestSignature());
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException();
    }
  }

  private Signature getSha256DigestSignature() throws NoSuchAlgorithmException {
    return Signature.getInstance("SHA256withNONE");
  }

  @Override
  public ConditionType getType() {
    return PreimageSha256Fulfillment.TYPE;
  }

  @Override
  public EnumSet<FeatureSuite> getFeatures() {
    return PreimageSha256Fulfillment.FEATURES;
  }

  @Override
  public int getSafeFulfillmentLength() {
    return OerUtil.MAX_INT;
  }

  @Override
  protected void validatePrivateKey(PrivateKey privateKey) throws InvalidKeyException {
    if (!(privateKey instanceof Sha256DigestPrivateKey)) {
      throw new InvalidKeyException("Supplied key is not a SHA-256 Preimage.");
    }
  }

  @Override
  protected void validateSignature(PrivateKey privateKey, byte[] signature)
      throws SignatureException {
    // No op
  }

  @Override
  protected Fulfillment getFulfillment(PrivateKey privateKey, byte[] signature)
      throws SignatureException {

    PreimageSha256FulfillmentImpl fulfillment = new PreimageSha256FulfillmentImpl();
    fulfillment.setPreimage(((Sha256DigestPrivateKey) privateKey).getPreimage());
    return fulfillment;
  }

  @Override
  protected PublicKey getInternalPublicKey(Fulfillment fulfillment) throws SignatureException {

    if (!(fulfillment instanceof PreimageSha256Fulfillment))
      throw new SignatureException(
          "Fulfillment is the wrong type. " + "Expected a PREIMAGE-SHA-256 fulfillment.");

    try {
      byte[] preimage = ((PreimageSha256Fulfillment) fulfillment).getPreimage();
      Signature sig = getSha256DigestSignature();
      sig.initSign(new Sha256DigestPrivateKey(preimage));
      byte[] digest = sig.sign();

      return new Sha256DigestPublicKey(digest);

    } catch (NoSuchAlgorithmException e) {
      throw new SignatureException(e);
    } catch (InvalidKeyException e) {
      throw new SignatureException(e);
    }

  }

  @Override
  protected byte[] getInternalSignature(Fulfillment fulfillment) throws SignatureException {
    if (!(fulfillment instanceof PreimageSha256Fulfillment))
      throw new SignatureException(
          "Fulfillment is the wrong type. " + "Expected a PREIMAGE-SHA-256 fulfillment.");

    try {
      byte[] preimage = ((PreimageSha256Fulfillment) fulfillment).getPreimage();
      Signature sig = getSha256DigestSignature();
      sig.initSign(new Sha256DigestPrivateKey(preimage));

      return sig.sign();

    } catch (NoSuchAlgorithmException e) {
      throw new SignatureException(e);
    } catch (InvalidKeyException e) {
      throw new SignatureException(e);
    }

  }


}
