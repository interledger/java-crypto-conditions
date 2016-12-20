package org.interledger.cryptoconditions;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public abstract class Sha256Condition extends EncodedCondition {

  private long cost;
  private byte[] fingerprint;  
  
  public Sha256Condition(long cost) {
    this.cost = cost;
  }
  
  @Override
  public abstract ConditionType getType();

  protected abstract byte[] getFingerprintContents();
  
  @Override
  public byte[] getFingerprint() {
    if(fingerprint == null) {
      fingerprint = getDigest(getFingerprintContents());    
    }
    
    return fingerprint.clone();
  }
  
  @Override
  public long getCost() {
    return cost;
  }
  
  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    Sha256Condition other = (Sha256Condition) obj;
    if (getType() != other.getType())
      return false;
    if (getCost() != other.getCost())
      return false;
    if (!Arrays.equals(getFingerprint(), other.getFingerprint()))
      return false;
    return true;
  }

  private static MessageDigest _DIGEST;
  
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
  
}
