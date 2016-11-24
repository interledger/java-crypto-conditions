package org.interledger.cryptoconditions.json;

import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;

import com.google.gson.annotations.JsonAdapter;

class JsonCondition {
  public JsonCondition(Condition condition) {
    type = condition.getType();
    features = condition.getFeatures();
    fingerprint = condition.getFingerprint();
    maxFulfillmentLength = condition.getMaxFulfillmentLength();
  }

  public ConditionType type;
  public EnumSet<FeatureSuite> features;
  @JsonAdapter(ByteArrayBase64UrlTypeAdaptor.class)
  public byte[] fingerprint;
  @JsonAdapter(IntegerBase16TypeAdaptor.class)
  public int maxFulfillmentLength;
}
