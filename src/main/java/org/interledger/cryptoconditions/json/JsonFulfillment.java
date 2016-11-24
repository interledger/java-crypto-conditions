package org.interledger.cryptoconditions.json;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Ed25519Fulfillment;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.FulfillmentException;
import org.interledger.cryptoconditions.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.RsaSha256Fulfillment;

class JsonFulfillment {
  public JsonFulfillment(Fulfillment fulfillment) {
    type = fulfillment.getType();

    switch (type) {
      case PREIMAGE_SHA256:
        payload = new JsonPreimageSha256FulfillmentPayload((PreimageSha256Fulfillment) fulfillment);
        break;
      case RSA_SHA256:
        payload = new JsonRsaSha256FulfillmentPayload((RsaSha256Fulfillment) fulfillment);
        break;
      case ED25519:
        payload = new JsonEd25519FulfillmentPayload((Ed25519Fulfillment) fulfillment);
        break;
      case PREFIX_SHA256:
        payload = new JsonPrefixSha256FulfillmentPayload((PrefixSha256Fulfillment) fulfillment);
        break;
      case THRESHOLD_SHA256:
      default:
        throw new FulfillmentException("Unknown condition type.");
    }
  }

  public JsonFulfillment(ConditionType type, JsonFulfillmentPayload payload) {
    this.type = type;
    this.payload = payload;
  }

  public ConditionType type;
  public JsonFulfillmentPayload payload;
}
