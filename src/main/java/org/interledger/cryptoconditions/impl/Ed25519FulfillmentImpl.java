package org.interledger.cryptoconditions.impl;

import java.util.EnumSet;


import org.interledger.cryptoconditions.Condition;

import org.interledger.cryptoconditions.impl.ConditionImpl;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Ed25519Fulfillment;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.oer.OerUtil;

/**
 * Implementation of an ED25519 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author earizon<enrique.arizon.benito@everis.com>
 * @author adrianhopebailie
 *
 */

public class Ed25519FulfillmentImpl implements Ed25519Fulfillment , Fulfillment {

  private byte[] publicKey;
  private byte[] signature;

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
  public byte[] getPublicKey() {
    return this.publicKey.clone();
  }

  public void setPublicKey(byte[] publicKey) {
    this.publicKey = publicKey.clone();
  }

  @Override
  public byte[] getSignature() {
    return this.signature.clone();
  }

  public void setSignature(byte[] signature) {
    this.signature = signature.clone();
  }

  @Override
  public Condition getCondition() {
	  byte[] fingerprint = this.getPublicKey();
	  return new ConditionImpl(TYPE, FEATURES, fingerprint, getSafeFulfillmentLength());
  }
  // @Override
  // public Condition computeCondition() {
  // if (getPublicKey() == null) {
  // throw new NullPointerException("Public Key is null.");
  // }
  //
  // try {
  // return new ConditionImpl(TYPE, FEATURES, getPublicKey().getEncoded() , FULFILLMENT_LENGTH);
  // } catch (Exception e) {
  // throw new RuntimeException(e.toString(), e);
  // }
  // }
  //
  // @Override
  // public boolean validate(byte[] message) {
  // if (getPublicKey() == null) {
  // throw new NullPointerException("Public Key is null.");
  // }
  // if (getSignature() == null) {
  // throw new NullPointerException("Signature is null.");
  // }
  //
  // try {
  // return Ed25519Signature.verify(getPublicKey(), message, getSignature());
  // } catch (Exception e) {
  // throw new RuntimeException(e.toString(), e);
  // }
  // }
  //
  // public static Ed25519FulfillmentImpl fromPrivateKeyAndMessage(EdDSAPrivateKey privateKey,
  // byte[] message) {
  // byte[] signature;
  // try {
  // signature = Ed25519Signature.sign(privateKey, message);
  // } catch (Exception e) {
  // throw new RuntimeException(e);
  // }
  //
  // Ed25519FulfillmentImpl f = new Ed25519FulfillmentImpl();
  // f.setPublicKey(Ed25519Signature.getPublicKeyFromPrivateKey(privateKey));
  // f.setSignature(signature);
  // return f;
  //
  // }

}
