package org.interledger.cryptoconditions;

import java.math.BigInteger;
import java.util.Arrays;

public class UnsignedBigInteger {

  public static byte[] toUnsignedByteArray(BigInteger value) {
    
    if (value.signum() < 0) {
      throw new IllegalArgumentException("value must be a positive BigInteger");
    }
    
    byte[] signedValue = value.toByteArray();
    if (signedValue[0] == 0x00) {
      Arrays.copyOfRange(signedValue, 1, signedValue.length);
    }
    
    return signedValue;
  }

  public static BigInteger fromUnsignedByteArray(byte[] value) {
    return new BigInteger(1, value);
  }

}
