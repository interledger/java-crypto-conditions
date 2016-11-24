package org.interledger.cryptoconditions.impl;

import java.math.BigInteger;
import java.util.EnumSet;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.oer.OerUtil;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * @author adrianhopebailie
 *
 */
public class RsaSha256FulfillmentImpl implements RsaSha256Fulfillment {

  private BigInteger modulus;
  private byte[] signature = null;

  @Override
  public ConditionType getType() {
    return TYPE;
  }

  @Override
  public EnumSet<FeatureSuite> getFeatures() {
    return FEATURES;
  }

  @Override
  public int getSafeFulfillmentLength() {
    return OerUtil.MAX_INT;
  }

  @Override
  public BigInteger getModulus() {
    return modulus;
  }

  public void setModulus(BigInteger modulus) {
    this.modulus = modulus;
  }

  @Override
  public byte[] getSignature() {
    return signature.clone();
  }

  public void setSignature(byte[] signature) {
    this.signature = signature.clone();
  }

  // @Override
  // public Condition computeCondition() {
  //
  // byte[] fingerprint = Sha256Digest.getDigest(
  // calculateFingerPrintContent(getPublicKey().getModulus().toByteArray()));
  //
  // int maxFulfillmentLength =
  // MAXIMUM_SIGNATURE_SIZE + 2 //Max + Length indicator
  // + MAXIMUM_MODULUS_SIZE + 2; //Max + Length indicator
  //
  // return new ConditionImpl(
  // TYPE,
  // FEATURES,
  // fingerprint,
  // maxFulfillmentLength);
  // }
  //
  // private byte[] calculateFingerPrintContent(byte[] modulus)
  // {
  // ByteArrayOutputStream buffer = new ByteArrayOutputStream();
  // ConditionOutputStream stream = new ConditionOutputStream(buffer);
  //
  // try {
  // stream.writeOctetString(modulus);
  // stream.flush();
  // return buffer.toByteArray();
  // } catch (IOException e) {
  // throw new RuntimeException(e);
  // } finally {
  // try {
  // stream.close();
  // } catch (IOException e) {
  // throw new RuntimeException(e);
  // }
  // }
  // }

}
