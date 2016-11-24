package org.interledger.cryptoconditions.oer;

import java.util.EnumSet;

import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.UnsupportedFeaturesException;

public class FeatureSuiteOerEncoding {

  public static int getBitmaskFromFeatures(EnumSet<FeatureSuite> featureSet) {

    int result = 0;

    for (FeatureSuite featureSuite : featureSet) {
      result = result | 1 << featureSuite.getBitIndex();
    }

    return result;
  }

  public static EnumSet<FeatureSuite> getFeaturesFromBitmask(int bitmask)
      throws UnsupportedFeaturesException {

    EnumSet<FeatureSuite> result = EnumSet.noneOf(FeatureSuite.class);

    for (FeatureSuite featureSuite : EnumSet.allOf(FeatureSuite.class)) {
      if ((bitmask & (1 << featureSuite.getBitIndex())) != 0) {
        result.add(featureSuite);

        // Unset bit to check we read them all
        bitmask &= ~(1 << featureSuite.getBitIndex());
      }
    }

    if (bitmask != 0)
      throw new UnsupportedFeaturesException("An unknown feature bit was set in the bitmask.");

    return result;
  }



}
