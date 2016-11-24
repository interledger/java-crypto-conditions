package org.interledger.cryptoconditions.json;

import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.PrefixSha256Fulfillment;

import com.google.gson.annotations.JsonAdapter;

class JsonPrefixSha256FulfillmentPayload implements JsonFulfillmentPayload {

  public JsonPrefixSha256FulfillmentPayload(PrefixSha256Fulfillment fulfillment) {
    prefix = fulfillment.getPrefix();
    subfulfillment = fulfillment.getSubfulfillment();
  }

  @JsonAdapter(ByteArrayBase16TypeAdaptor.class)
  public byte[] prefix;
  @JsonAdapter(FulfillmentTypeAdaptor.class)
  public Fulfillment subfulfillment;

}
