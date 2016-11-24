package org.interledger.cryptoconditions.jce.interfaces;

import java.security.PrivateKey;

import org.interledger.cryptoconditions.Condition;

public interface PrefixedFulfillmentPrivateKey extends PrivateKey {

  byte[] getPrefix();

  Condition getSubcondition();

  PrivateKey getInternalPrivateKey();

}
