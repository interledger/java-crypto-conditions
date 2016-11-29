package org.interledger.cryptoconditions;

import java.util.EnumSet;

public interface PrefixSha256Fulfillment {

  static final ConditionType TYPE = ConditionType.PREFIX_SHA256;
  static final EnumSet<FeatureSuite> FEATURES =
      EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.PREFIX);

  byte[] getPrefix();

  Fulfillment getSubfulfillment();

}
