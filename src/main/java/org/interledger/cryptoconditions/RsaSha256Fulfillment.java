package org.interledger.cryptoconditions;

import java.math.BigInteger;
import java.util.EnumSet;

public interface RsaSha256Fulfillment {

  static final ConditionType TYPE = ConditionType.RSA_SHA256;
  static final EnumSet<FeatureSuite> FEATURES =
      EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.RSA_PSS);

  static final BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65537);

  static final int MINIMUM_MODULUS_SIZE = 128;
  static final int MAXIMUM_MODULUS_SIZE = 512;
  static final int MINIMUM_SIGNATURE_SIZE = 128;
  static final int MAXIMUM_SIGNATURE_SIZE = 512;

  BigInteger getModulus();

  byte[] getSignature();

}
