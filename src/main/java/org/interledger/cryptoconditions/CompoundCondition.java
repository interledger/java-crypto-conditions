package org.interledger.cryptoconditions;

import java.util.EnumSet;

public interface CompoundCondition extends Condition {
  
  EnumSet<ConditionType> getSubtypes();

}
