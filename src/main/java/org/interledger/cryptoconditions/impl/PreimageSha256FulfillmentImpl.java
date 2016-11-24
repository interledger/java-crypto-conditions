package org.interledger.cryptoconditions.impl;

import java.util.EnumSet;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.oer.OerUtil;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256FulfillmentImpl implements PreimageSha256Fulfillment {

  private byte[] preimage = null;

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
  }

  @Override
  public byte[] getPreimage() {
    return this.preimage.clone();
  }

}
