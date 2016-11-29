package org.interledger.cryptoconditions;

import java.util.EnumSet;

public interface Ed25519Fulfillment {

  static final ConditionType TYPE = ConditionType.ED25519;
  static final EnumSet<FeatureSuite> FEATURES =
      EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.ED25519);

  static final int PUBKEY_LENGTH = 32;
  static final int SIGNATURE_LENGTH = 64;

  byte[] getPublicKey();

  byte[] getSignature();
}
