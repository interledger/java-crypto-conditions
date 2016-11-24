package org.interledger.cryptoconditions.json;

import java.io.IOException;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.FulfillmentException;
import org.interledger.cryptoconditions.impl.Ed25519FulfillmentImpl;
import org.interledger.cryptoconditions.impl.PrefixSha256FulfillmentImpl;
import org.interledger.cryptoconditions.impl.PreimageSha256FulfillmentImpl;
import org.interledger.cryptoconditions.impl.RsaSha256FulfillmentImpl;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.google.gson.stream.JsonReader;

public class FulfillmentJsonReader {

  private static Gson gson = new Gson();

  public static Fulfillment nextFulfillment(JsonReader reader) throws IOException {

    // TODO Support properties in different order

    reader.beginObject();
    ConditionType type = nextConditiontype(reader);
    if (!"payload".equals(reader.nextName()))
      throw new JsonParseException("Expected payload.");
    JsonFulfillmentPayload payload = nextPayload(reader, type);
    reader.endObject();

    switch (type) {
      case PREIMAGE_SHA256:

        PreimageSha256FulfillmentImpl preimageFulfillment = new PreimageSha256FulfillmentImpl();
        preimageFulfillment.setPreimage(((JsonPreimageSha256FulfillmentPayload) payload).preimage);
        return preimageFulfillment;

      case RSA_SHA256:

        RsaSha256FulfillmentImpl rsaFulfillment = new RsaSha256FulfillmentImpl();
        rsaFulfillment.setModulus(((JsonRsaSha256FulfillmentPayload) payload).modulus);
        rsaFulfillment.setSignature(((JsonRsaSha256FulfillmentPayload) payload).signature);
        return rsaFulfillment;

      case ED25519:

        Ed25519FulfillmentImpl ed25519Fulfillment = new Ed25519FulfillmentImpl();
        ed25519Fulfillment.setPublicKey(((JsonEd25519FulfillmentPayload) payload).publicKey);
        ed25519Fulfillment.setSignature(((JsonEd25519FulfillmentPayload) payload).signature);
        return ed25519Fulfillment;

      case PREFIX_SHA256:

        PrefixSha256FulfillmentImpl prefixedFulfillment = new PrefixSha256FulfillmentImpl();
        prefixedFulfillment.setPrefix(((JsonPrefixSha256FulfillmentPayload) payload).prefix);
        prefixedFulfillment
            .setSubfulfillment(((JsonPrefixSha256FulfillmentPayload) payload).subfulfillment);
        return prefixedFulfillment;
      case THRESHOLD_SHA256:
      default:
        throw new FulfillmentException("Unknown fulfillment type.");

    }
  }

  public static JsonFulfillmentPayload nextPayload(JsonReader reader, ConditionType type) {

    switch (type) {
      case PREIMAGE_SHA256:
        return gson.fromJson(reader, JsonPreimageSha256FulfillmentPayload.class);
      case RSA_SHA256:
        return gson.fromJson(reader, JsonRsaSha256FulfillmentPayload.class);
      case ED25519:
        return gson.fromJson(reader, JsonEd25519FulfillmentPayload.class);
      case PREFIX_SHA256:
        return gson.fromJson(reader, JsonPrefixSha256FulfillmentPayload.class);
      case THRESHOLD_SHA256:
      default:
        throw new FulfillmentException("Unknown condition type.");
    }
  }

  public static ConditionType nextConditiontype(JsonReader reader) throws IOException {

    String typeName = reader.nextString();
    return ConditionType.valueOf(typeName);

  }

  /**
   * Reads the next name and ensures it matches the provided value.
   * 
   * @param expectedName
   * @throws IOException
   * @throws JsonParseException if the name that is read from the stream is different to the
   *         supplied value
   */
  public static void nextName(JsonReader reader, String expectedName) throws IOException {
    String name = reader.nextName();
    if (!name.equals(expectedName))
      throw new JsonParseException(
          "Expected property name '" + expectedName + "' " + "and got '" + name + "'.");

  }


}
