package org.interledger.cryptoconditions.json;

import java.io.IOException;
import java.io.StringReader;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.impl.ConditionImpl;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

public class JsonUtil {

  private static Gson gson = new Gson();

  public static String toJson(Condition condition) {
    return gson.toJson(new JsonCondition(condition));
  }

  public static String toJson(Fulfillment fulfillment) {
    return gson.toJson(new JsonFulfillment(fulfillment));
  }

  public static Condition conditionFromJson(String json) {

    final JsonCondition condition = gson.fromJson(json, JsonCondition.class);

    return new ConditionImpl(condition.type, condition.features, condition.fingerprint,
        condition.maxFulfillmentLength);
  }

  public static Fulfillment fulfillmentFromJson(String json) throws IOException {
    JsonReader reader = new JsonReader(new StringReader(json));
    try {
      return FulfillmentJsonReader.nextFulfillment(reader);
    } finally {
      reader.close();
    }
  }


}
