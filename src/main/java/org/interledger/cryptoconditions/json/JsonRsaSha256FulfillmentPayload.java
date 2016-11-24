package org.interledger.cryptoconditions.json;

import java.math.BigInteger;

import org.interledger.cryptoconditions.RsaSha256Fulfillment;

import com.google.gson.annotations.JsonAdapter;

class JsonRsaSha256FulfillmentPayload implements JsonFulfillmentPayload {

  public JsonRsaSha256FulfillmentPayload(RsaSha256Fulfillment fulfillment) {
    modulus = fulfillment.getModulus();
    signature = fulfillment.getSignature();
  }

  @JsonAdapter(UnsignedBigIntegerBase16TypeAdaptor.class)
  public BigInteger modulus;
  @JsonAdapter(ByteArrayBase16TypeAdaptor.class)
  public byte[] signature = null;

}
