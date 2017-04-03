package org.interledger.cryptoconditions;

public interface Fulfillment {

  ConditionType getType();

  byte[] getEncoded();

  Condition getCondition();

  /*
   *  TODO:(0) change signature
   *  verify(Condition condition, byte[] message) -> verify(byte[] message)
   *  (condition must be "fetched" from the internal getCondition
   *  in a similar way to the JS API)
   */

  boolean verify(Condition condition, byte[] message); // TODO:(?) In JS code is called validate. Rename?

}
