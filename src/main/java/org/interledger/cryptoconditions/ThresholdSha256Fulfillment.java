package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

public class ThresholdSha256Fulfillment implements Fulfillment {

  private ThresholdSha256Condition condition;
  private Condition[] subconditions;
  private Fulfillment[] subfulfillments;
  
  public ThresholdSha256Fulfillment(Condition[] subconditions, Fulfillment[] subfulfillments) {
    this.subconditions = new Condition[subconditions.length];
    System.arraycopy(subconditions, 0, this.subconditions, 0, subconditions.length);
    
    //TODO Clone each fulfillment?
    this.subfulfillments = new Fulfillment[subfulfillments.length];
    System.arraycopy(subfulfillments, 0, this.subfulfillments, 0, subfulfillments.length);
    
  }
  
  @Override
  public ConditionType getType() {
    return ConditionType.THRESHOLD_SHA256;
  }

  @Override
  public byte[] getEncoded() {
    try {
      //Build subcondition sequence
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DEROutputStream out = new DEROutputStream(baos);
      for (int i = 0; i < subconditions.length; i++) {
        out.writeOctetString(subconditions[i].getEncoded());
      }
      out.close();
      byte[] conditionsBuffer = baos.toByteArray();

      //Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.SET_OF.getTag(),
          conditionsBuffer);
      out.close();
      conditionsBuffer = baos.toByteArray();
      
      //Build subfulfillment sequence
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      for (int i = 0; i < subfulfillments.length; i++) {
        out.writeOctetString(subfulfillments[i].getEncoded());
      }
      out.close();
      byte[] fulfillmentsBuffer = baos.toByteArray();

      //Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.SET_OF.getTag(),
          fulfillmentsBuffer);
      out.close();
      fulfillmentsBuffer = baos.toByteArray();

      byte[] buffer = new byte[conditionsBuffer.length + fulfillmentsBuffer.length];
      System.arraycopy(fulfillmentsBuffer, 0, buffer, 0, fulfillmentsBuffer.length);
      System.arraycopy(conditionsBuffer, 0, buffer, fulfillmentsBuffer.length, conditionsBuffer.length);
      
      //Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.SEQUENCE.getTag(),
          buffer);
      out.close();
      
      //Wrap CHOICE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.TAGGED.getTag() + 
          getType().getTypeCode(),
          buffer
      );
      out.close();

      return baos.toByteArray();
      
    } catch (IOException e) {
      throw new RuntimeException("DER Encoding Error", e);
    }
  }

  @Override
  public ThresholdSha256Condition getCondition() {
    if(condition == null) {
      
      //Copy all subconditions into another array along with the conditions derived from all subfulfillments
      Condition[] allConditions = new Condition[subconditions.length + subfulfillments.length];
      System.arraycopy(subconditions, 0, allConditions, 0, subconditions.length);
      
      int j = subconditions.length;
      for(int i = 0; i < subfulfillments.length; i++) {
        allConditions[j] = subfulfillments[i].getCondition();
        j++;
      }
      condition = new ThresholdSha256Condition(subfulfillments.length, allConditions);
    }
    return condition;
  }

  @Override
  public boolean verify(Condition condition, byte[] message) {
    
    if(condition == null) {
      throw new IllegalArgumentException("Can't verify a ThresholdSha256Fulfillment against an null condition.");
    }
    
    if(!(condition instanceof ThresholdSha256Condition)) {
      throw new IllegalArgumentException("Must verify a ThresholdSha256Fulfillment against ThresholdSha256Condition.");
    }
    
    if(!getCondition().equals(condition)) {
      return false;
    }

    for (int i = 0; i < subfulfillments.length; i++) {
      Condition subcondition = subfulfillments[i].getCondition();
      if(!subfulfillments[i].verify(subcondition, message)) {
        return false;
      }
    }
    
    return true;

  }

}
