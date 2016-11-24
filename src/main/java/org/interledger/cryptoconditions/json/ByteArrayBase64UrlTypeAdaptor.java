package org.interledger.cryptoconditions.json;

import java.io.IOException;

import org.interledger.cryptoconditions.util.Base64Url;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

public class ByteArrayBase64UrlTypeAdaptor extends TypeAdapter<byte[]> {

  @Override
  public void write(JsonWriter out, byte[] value) throws IOException {
    out.value(Base64Url.encode(value));
  }

  @Override
  public byte[] read(JsonReader in) throws IOException {
    String base64String = in.nextString();
    return Base64Url.decode(base64String);
  }

}
