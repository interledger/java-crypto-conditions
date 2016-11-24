package org.interledger.cryptoconditions;

import java.util.EnumSet;

/**
 * Enumeration of crypto-condition types
 * 
 * @author adrianhopebailie
 *
 */
public enum ConditionType {

  PREIMAGE_SHA256(0, "PREIMAGE-SHA-256"), PREFIX_SHA256(1, "PREFIX-SHA-256"), THRESHOLD_SHA256(2,
      "THRESHOLD-SHA-256"), RSA_SHA256(3, "RSA-SHA-256"), ED25519(4, "ED25519");


  private final int typeCode;
  private final String name;

  ConditionType(int typeCode, String algorithmName) {
    this.typeCode = typeCode;
    this.name = algorithmName;
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

  public static ConditionType valueOf(int typeCode) {

    for (ConditionType conditionType : EnumSet.allOf(ConditionType.class)) {
      if (typeCode == conditionType.typeCode)
        return conditionType;
    }

    throw new IllegalArgumentException("Invalid Condition Type code.");
  }

}
