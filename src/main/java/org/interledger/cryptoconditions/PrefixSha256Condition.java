package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.EnumSet;

import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

public class PrefixSha256Condition extends Sha256Condition implements CompoundCondition {

  private byte[] prefix;
  private long maxMessageLength;
  private Condition subcondition;
  
  public PrefixSha256Condition(byte[] prefix, long maxMessageLength, Condition subcondition) {
    super(calculateCost(prefix, maxMessageLength, subcondition.getCost()));
    this.prefix = new byte[prefix.length];
    System.arraycopy(prefix, 0, this.prefix, 0, prefix.length);
    this.maxMessageLength = maxMessageLength;
    this.subcondition = subcondition;
  }
  
  @Override
  public ConditionType getType() {
    return ConditionType.PREFIX_SHA256;
  }

  @Override
  protected byte[] getFingerprintContents() {
    
    try {
      //Build prefix and subcondition
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DEROutputStream out = new DEROutputStream(baos);
      out.writeOctetString(prefix);
      out.writeInteger(BigInteger.valueOf(maxMessageLength));
      out.writeOctetString(subcondition.getEncoded());
      out.close();
      byte[] buffer = baos.toByteArray();

      //Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.SEQUENCE.getTag(),
          buffer);
      out.close();
      return baos.toByteArray();
      
    } catch (IOException e) {
      throw new RuntimeException("DER Encoding Error", e);
    }
    
  }
  
  /**
   * cost = length_of_prefix + max_message_length + subcondition_cost + 1024
   * 
   * @param prefix
   * @param maxMessageLength
   * @param subconditionCost
   * @return
   */
  private static long calculateCost(byte[] prefix, long maxMessageLength, long subconditionCost) {
    
    return prefix.length + maxMessageLength + subconditionCost + 1024l; 
  }

  @Override
  public EnumSet<ConditionType> getSubtypes() {
    return EnumSet.of(this.subcondition.getType());
  }


}
