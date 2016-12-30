package org.interledger.cryptoconditions;

import java.util.EnumSet;

/**
 * Enumeration of crypto-condition types
 * 
 * @author adrianhopebailie
 *
 */
public enum ConditionType {

  PREIMAGE_SHA256(0, "PREIMAGE-SHA-256", 0x01), 
  PREFIX_SHA256(1, "PREFIX-SHA-256", 0x02), 
  THRESHOLD_SHA256(2, "THRESHOLD-SHA-256", 0x04), 
  RSA_SHA256(3, "RSA-SHA-256", 0x08), 
  ED25519_SHA256(4, "ED25519-SHA-256", 0x10);

  private final int typeCode;
  private final String name;
  private final int flag;

  ConditionType(int typeCode, String algorithmName, int flag) {
    this.typeCode = typeCode;
    this.name = algorithmName;
    this.flag = flag;
  }

  /**
   * Get the ASN.1 enum code for this type
   * 
   * @return the ASN.1 enumeration number
   */
  public int getTypeCode() {
    return this.typeCode;
  }

  @Override
  public String toString() {
    return this.name;
  }

  public int getFlag() {
    return this.flag;
  }

  public static ConditionType valueOf(int typeCode) {

    for (ConditionType conditionType : EnumSet.allOf(ConditionType.class)) {
      if (typeCode == conditionType.typeCode)
        return conditionType;
    }

    throw new IllegalArgumentException("Invalid Condition Type code.");
  }

  /**
   * Convert a set of types into a byte that can be used to encode a BIT STRING
   * 
   * TODO This will break if the possible types exceeds 8. Only works for our current known set
   * 
   * @param types set of types to encode as a BIT STRING
   * @return byte array where first byte indicates the number of unused bits in last byte and
   *         remaining bytes encode the bit string
   */
  public static byte[] getEnumOfTypesAsBitString(EnumSet<ConditionType> types) {

    int data = 0;
    int lastUsedBit = -1;
    
    //No guarantee that iterating through the types will be done in order so just test for each
    if(types.contains(PREIMAGE_SHA256)){
      data += ConditionType.PREIMAGE_SHA256.getFlag();
      lastUsedBit = PREIMAGE_SHA256.getTypeCode();
    }
    
    if(types.contains(PREFIX_SHA256)){
      data += ConditionType.PREFIX_SHA256.getFlag();
      lastUsedBit = PREFIX_SHA256.getTypeCode();
    }
    
    if(types.contains(THRESHOLD_SHA256)){
      data += ConditionType.THRESHOLD_SHA256.getFlag();
      lastUsedBit = THRESHOLD_SHA256.getTypeCode();
    }
    
    if(types.contains(RSA_SHA256)){
      data += ConditionType.RSA_SHA256.getFlag();
      lastUsedBit = RSA_SHA256.getTypeCode();
    }
    
    if(types.contains(ED25519_SHA256)){
      data += ConditionType.ED25519_SHA256.getFlag();
      lastUsedBit = ED25519_SHA256.getTypeCode();
    }
    
    if(lastUsedBit > -1) {
      return new byte[] {(byte) (7 - lastUsedBit), (byte) data};
    }
    else
    {
      return new byte[] {(byte) 0x00 };
    }

  }

  /**
   * Convert a set of types into a commas separated list
   * 
   * @param types set of types to encode
   */
  public static String getEnumOfTypesAsString(EnumSet<ConditionType> types) {

    String[] names = new String[types.size()];
    int i = 0;
    for (ConditionType conditionType : types) {
      names[i++] = conditionType.name().toLowerCase();
    }

    return String.join(",", names);

  }

}
