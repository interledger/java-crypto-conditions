package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;

import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

public class ThresholdSha256Condition extends Sha256Condition implements CompoundCondition {

  private int threshold;
  private Condition[] subconditions;
  
  public ThresholdSha256Condition(int threshold, Condition[] subconditions) {
    super(calculateCost(threshold, subconditions));
    this.threshold = threshold;
    this.subconditions = Arrays.copyOf(subconditions, subconditions.length);
    sortConditions(this.subconditions);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.THRESHOLD_SHA256;
  }

  @Override
  protected byte[] getFingerprintContents() {
    try {
      //Build subcondition sequence
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DEROutputStream out = new DEROutputStream(baos);
      for (int i = 0; i < subconditions.length; i++) {
        out.writeOctetString(subconditions[i].getEncoded());
      }
      out.close();
      byte[] buffer = baos.toByteArray();

      //Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.SET_OF.getTag(),
          buffer);
      out.close();
      buffer = baos.toByteArray();
      
      //Build threshold and subconditions sequence
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeInteger(BigInteger.valueOf(threshold));
      out.writeOctetString(buffer);
      out.close();
      buffer = baos.toByteArray();

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
   * Sort the given array in ascending lexicographic order
   * 
   * @param conditions an array of Conditions to sort.
   */
  private static void sortConditions(Condition[] conditions) {
    Arrays.sort(conditions, (Comparator<? super Condition>) (Condition c1, Condition c2) -> {
      byte[] c1encoded = c1.getEncoded();
      byte[] c2encoded = c2.getEncoded();
            
      int minLength = Math.min(c1encoded.length, c2encoded.length);
      for (int i = 0; i < minLength; i++) {
        int result = Byte.compare(c1encoded[i], c2encoded[i]);
        if (result != 0) {
          return result;
        }
      }
      return c1encoded.length - c2encoded.length;
    });
  }
  
  private static long calculateCost(int threshold, Condition[] subconditions) {
    
    //sum(biggest(t, subcondition_costs)) + 1024 * n
    
    //Sort by cost
    Condition[] sortedConditions = Arrays.copyOf(subconditions, subconditions.length);
    Arrays.sort(sortedConditions, (Comparator<? super Condition>) (Condition c1, Condition c2) -> {
      return (int) (c2.getCost() - c1.getCost());
    });
    
    long largestCosts = 0;
    for (int i = 0; i < threshold; i++) {
      largestCosts += subconditions[i].getCost();
    }
    
    return largestCosts + (subconditions.length * 1024);
  }

  @Override
  public EnumSet<ConditionType> getSubtypes() {
    
    EnumSet<ConditionType> subtypes = EnumSet.noneOf(ConditionType.class);
    for (int i = 0; i < subconditions.length; i++) {
      subtypes.add(subconditions[i].getType());
      if(subconditions[i] instanceof CompoundCondition) {
        subtypes.addAll(((CompoundCondition) subconditions[i]).getSubtypes());
      }
    }
    
    //Remove our own type
    if(subtypes.contains(getType())) {
      subtypes.remove(getType());
    }
    
    return subtypes;
  }  
}