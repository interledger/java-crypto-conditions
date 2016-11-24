package org.interledger.cryptoconditions.jce.spec;

import java.security.spec.KeySpec;

import org.interledger.cryptoconditions.Fulfillment;

public class FulfillmentKeySpec implements KeySpec {

  private Fulfillment fulfillment;

  public FulfillmentKeySpec(Fulfillment fulfillment) {
    this.fulfillment = fulfillment;
  }

  public Fulfillment getFulfillment() {
    return this.fulfillment;
  }

}
