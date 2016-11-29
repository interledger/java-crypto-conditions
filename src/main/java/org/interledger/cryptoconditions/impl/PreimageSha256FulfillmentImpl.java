package org.interledger.cryptoconditions.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.oer.OerUtil;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256FulfillmentImpl implements Fulfillment, PreimageSha256Fulfillment {

  private byte[] preimage = null;

  private static MessageDigest _DIGEST = null;

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

  public void setPreimage(byte[] preimage) {
    this.preimage = preimage.clone();
    _DIGEST = null ; // Note: earizon If the code is not immutable this bug will repeat.
  }

  @Override
  public byte[] getPreimage() {
    return this.preimage.clone();
  }
  
  private static byte[] getDigest(byte[] input) {
    if (_DIGEST == null) {
      try {
        _DIGEST = MessageDigest.getInstance("SHA-256");
      } catch (NoSuchAlgorithmException e) {
    	  throw new RuntimeException(e);
      }
    }
    
    return _DIGEST.digest(input);
  }

  
  @Override
  public Condition getCondition() {
      byte[] preimage = getPreimage();
      byte[] fingerprint = getDigest(preimage);
      return new ConditionImpl(TYPE, FEATURES, fingerprint, getSafeFulfillmentLength());
  }

}
