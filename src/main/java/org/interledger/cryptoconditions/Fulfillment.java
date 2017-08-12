package org.interledger.cryptoconditions;

public interface Fulfillment {

  CryptoConditionType getType();

  Condition getCondition();

  boolean verify(Condition condition, byte[] message);

}
