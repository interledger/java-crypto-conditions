package org.interledger.cryptoconditions;

import java.util.EnumSet;

public interface PreimageSha256Fulfillment extends Fulfillment {

  static final ConditionType TYPE = ConditionType.PREIMAGE_SHA256;
  static final EnumSet<FeatureSuite> FEATURES =
      EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.PREIMAGE);

  byte[] getPreimage();

}
