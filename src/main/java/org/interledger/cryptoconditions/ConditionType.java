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
      //the bit strings are *right* padded with binary 0.
      data = data << (7 - lastUsedBit);
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
      names[i++] = conditionType.toString().toLowerCase();
    }

    return String.join(",", names);

  }

  /**
   * Returns the Condition type identified by its name, in a *case-insensitive* manner.
   *
   * @param typeName
   *  The name of the condition type, e.g. 'rsa-sha-256'
   * @return
   *  The Condition type with matching name, if any.
   */
  public static ConditionType fromString(String typeName) {
    for (ConditionType conditionType : EnumSet.allOf(ConditionType.class)) {
      if (conditionType.name.equalsIgnoreCase(typeName))
        return conditionType;
    }

    throw new IllegalArgumentException("Invalid Condition Type name.");
  }
  
  /**
   * Convert a comma separated list of types into a set of types
   * 
   * @param types comma separated list of type names
   */
  public static EnumSet<ConditionType> getEnumOfTypesFromString(String subtypes) {
    EnumSet<ConditionType> types = EnumSet.noneOf(ConditionType.class);
    
    if (subtypes == null || subtypes.trim().isEmpty()) {
      return types;
    }
    
    String[] names = subtypes.split(",");
    for (String typeName : names) {
      types.add(ConditionType.fromString(typeName));
    }

    return types;
  }  
  
  /**
   * Get the set of types represented by
   * 
   * @param bitStringData a raw BIT STRING including the padding bit count in the first byte
   * @return
   */
  public static EnumSet<ConditionType> getEnumOfTypesFromBitString(byte[] bitStringData) {

    // We only have 5 known types so shouldn't be more than a padding byte and the bitmap
    if (bitStringData.length > 2) {
      throw new IllegalArgumentException("Unknown types in bit string.");
    }

    if (bitStringData.length == 1) {
      throw new IllegalArgumentException("Corrupt bit string.");
    }

    EnumSet<ConditionType> subtypes = EnumSet.noneOf(ConditionType.class);
    if (bitStringData.length == 0) {
      return subtypes;
    }

    int padBits = bitStringData[0];

    // We only have 5 known types so should have at least 3 padding bits
    if (padBits < 3) {
      throw new IllegalArgumentException("Unknown types in bit string.");
    }
    
    //our flags are based on *right aligned* boundaries, but the byte we have has been 
    //*right padded*, so we arent looking in the correct place. we must shift the entire bit mask
    //over to the right by the number of padding bits. by way of example, our bit string is just '1'
    // this is padded ON THE RIGHT to the nearest 8 bit boundary: '1 000 0000'
    // the number of bits added as padding is then prefixed, producing: 0x 07 80.
    //clearly, the 1 we are looking for as the LEAST SIGNIFICANT bit has been shifted.
    
    //shift everything over so that we are back to being right aligned.
    //sadly java's bytes are 2's complements, so direct shifting gives very odd results.
    //try 0x80 >> 7 vs ((byte)0x80) >> 7
    int mask = (Byte.toUnsignedInt(bitStringData[1]) >> padBits);

    // We only expect 1 byte of data so let's keep it simple
    for (ConditionType type : ConditionType.values()) {
      if ((mask & type.getFlag()) == type.getFlag()) {
        subtypes.add(type);
      }
    }

    return subtypes;
  }  
}
