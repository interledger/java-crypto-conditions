package org.interledger.cryptoconditions.impl;

import java.util.EnumSet;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.oer.OerUtil;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 * 
 * @author adrianhopebailie
 *
 */
public class PrefixSha256FulfillmentImpl implements PrefixSha256Fulfillment {


  private byte[] prefix;
  private Fulfillment subfulfillment;

  @Override
  public ConditionType getType() {
    return TYPE;
  }

  @Override
  public EnumSet<FeatureSuite> getFeatures() {
    EnumSet<FeatureSuite> features = EnumSet.copyOf(FEATURES);
    features.addAll(subfulfillment.getFeatures());
    return features;
  }

  @Override
  public int getSafeFulfillmentLength() {
    return OerUtil.MAX_INT;
  }


  @Override
  public byte[] getPrefix() {
    return prefix.clone();
  }

  public void setPrefix(byte[] prefix) {
    this.prefix = prefix.clone();
  }


  public void setSubfulfillment(Fulfillment fulfillment) {
    // TODO: Defensive copy
    this.subfulfillment = fulfillment;
  }


  @Override
  public Fulfillment getSubfulfillment() {
    // TODO: Defensive copy
    return this.subfulfillment;
  }

  // @Override
  // public Condition computeCondition() {
  // Condition subcondition = subfulfillment.computeCondition();
  //
  // EnumSet<FeatureSuite> features = subcondition.getFeatures();
  // features.addAll(FEATURES);
  //
  // byte[] fingerprint = Sha256Digest.getDigest(
  // calculateFingerPrintContent(
  // prefix,
  // subcondition
  // )
  // );
  //
  // int maxFulfillmentLength = calculateMaxFulfillmentLength(
  // prefix,
  // subcondition
  // );
  //
  // return new ConditionImpl(
  // ConditionType.PREFIX_SHA256,
  // features,
  // fingerprint,
  // maxFulfillmentLength);
  // }
  //
  // private byte[] calculateFingerPrintContent(byte[] prefix, Condition subcondition)
  // {
  //
  // ByteArrayOutputStream buffer = new ByteArrayOutputStream();
  // ConditionOutputStream stream = new ConditionOutputStream(buffer);
  //
  // try {
  // stream.writeOctetString(prefix);
  // stream.writeCondition(subcondition);
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
  //
  // private int calculateMaxFulfillmentLength(byte[] prefix, Condition subcondition)
  // {
  // int length = prefix.length;
  // if(length < 128)
  // {
  // length = length + 1;
  // } else if(length <= 255) {
  // length = length + 2;
  // } else if (length <= 65535) {
  // length = length + 3;
  // } else if (length <= 16777215){
  // length = length + 4;
  // } else {
  // throw new IllegalArgumentException("Field lengths of greater than 16777215 are not
  // supported.");
  // }
  // return length + subcondition.getMaxFulfillmentLength();
  // }

  // public void sign(byte[] message) throws SignatureException {
  //
  // byte[] prefixMessage = Arrays.copyOf(this.prefix, this.prefix.length + message.length);
  // System.arraycopy(message, 0, prefixMessage, this.prefix.length, message.length);
  //
  // subfulfillment.sign(prefixMessage);
  // }
  //
  // public boolean validate(byte[] message) {
  //
  // if (this.prefix == null)
  // throw new NullPointerException("Prefix is null.");
  //
  // if (this.subfulfillment == null)
  // throw new NullPointerException("Subfulfillment is null.");
  //
  // byte[] prefixMessage = Arrays.copyOf(this.prefix, this.prefix.length + message.length);
  // System.arraycopy(message, 0, prefixMessage, this.prefix.length, message.length);
  //
  // return this.subfulfillment.validate(prefixMessage);
  // }

}
