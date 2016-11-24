package org.interledger.cryptoconditions.json;

import java.io.IOException;

import org.interledger.cryptoconditions.Fulfillment;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

public class FulfillmentTypeAdaptor extends TypeAdapter<Fulfillment> {

  @Override
  public void write(JsonWriter out, Fulfillment value) throws IOException {
    out.value(JsonUtil.toJson(value));
  }

  @Override
  public Fulfillment read(JsonReader in) throws IOException {
    return FulfillmentJsonReader.nextFulfillment(in);
  }

}
