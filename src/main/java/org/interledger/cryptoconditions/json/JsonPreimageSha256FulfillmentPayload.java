package org.interledger.cryptoconditions.json;

import org.interledger.cryptoconditions.PreimageSha256Fulfillment;

import com.google.gson.annotations.JsonAdapter;

class JsonPreimageSha256FulfillmentPayload implements JsonFulfillmentPayload {

  public JsonPreimageSha256FulfillmentPayload(PreimageSha256Fulfillment fulfillment) {
    preimage = fulfillment.getPreimage();
  }

  @JsonAdapter(ByteArrayBase16TypeAdaptor.class)
  public byte[] preimage = null;

}
