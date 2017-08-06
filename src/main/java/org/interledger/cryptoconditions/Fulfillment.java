package org.interledger.cryptoconditions;

public interface Fulfillment {

  ConditionType getType();

  Condition getCondition();

  boolean verify(Condition condition, byte[] message);

}
