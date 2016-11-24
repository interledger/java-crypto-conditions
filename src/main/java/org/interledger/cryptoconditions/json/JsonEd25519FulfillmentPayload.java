package org.interledger.cryptoconditions.json;

import org.interledger.cryptoconditions.Ed25519Fulfillment;

import com.google.gson.annotations.JsonAdapter;

class JsonEd25519FulfillmentPayload implements JsonFulfillmentPayload {

  public JsonEd25519FulfillmentPayload(Ed25519Fulfillment fulfillment) {
    publicKey = fulfillment.getPublicKey();
    signature = fulfillment.getSignature();
  }

  @JsonAdapter(ByteArrayBase16TypeAdaptor.class)
  public byte[] publicKey;
  @JsonAdapter(ByteArrayBase16TypeAdaptor.class)
  public byte[] signature;

}
