package org.interledger.cryptoconditions.test;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;

/**
 * @deprecated Determine if this class should be removed since issues #52 allows URIs to be compared
 * for string equality.
 */
@Deprecated
public class CryptoConditionAssert {


  /**
   * Asserts the the set of types given are equal.
   *
   * @param message  A detail message to record if the assertion fails.
   * @param expected A list of expected condition types.
   * @param actual   A set of condition types to compare against the ones expected.
   */
  public static void assertSetOfTypesIsEqual(String message, List<String> expected,
      EnumSet<ConditionType> actual) {
    EnumSet<ConditionType> expectedSet = ConditionType
        .getEnumOfTypesFromString(String.join(",", expected.toArray(new String[expected.size()])));

    if (!expectedSet.containsAll(actual)) {
      throw new AssertionError(message + " - expected does not contain all values from actual.");
    }
    expectedSet.removeAll(actual);
    if (!expectedSet.isEmpty()) {
      throw new AssertionError(message + " - expected contains values not in actual.");
    }
  }

}
