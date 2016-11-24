package org.interledger.cryptoconditions.jce.spec;

import java.security.spec.KeySpec;

import org.interledger.cryptoconditions.Condition;

public class ConditionKeySpec implements KeySpec {

  private Condition condition;

  public ConditionKeySpec(Condition condition) {
    this.condition = condition;
  }

  public Condition getCondition() {
    return this.condition;
  }

}
