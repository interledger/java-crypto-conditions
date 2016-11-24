package org.interledger.cryptoconditions;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.impl.ConditionImpl;
import org.interledger.cryptoconditions.uri.UriEncoding;
import org.junit.Test;

public class TestConditionImpl {

  @Test
  public void testURISerialization() {
    String URICondition = "cc:2:3:x07W1xU1_oBcV9zUheOzspx6Beq8vgy0vYgBVifNV1Q:43";
    String fingerprint = "x07W1xU1_oBcV9zUheOzspx6Beq8vgy0vYgBVifNV1Q";

    EnumSet<FeatureSuite> fs = EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.THRESHOLD);

    Condition condition = new ConditionImpl(ConditionType.THRESHOLD_SHA256, fs,
        fingerprint.getBytes(), fingerprint.length());
    try {
      assertTrue(URICondition.equals(UriEncoding.toUri(condition)));
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
      fail();
    }
  }

}
