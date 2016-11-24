package org.interledger.cryptoconditions.json;

import java.io.IOException;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

public class IntegerBase16TypeAdaptor extends TypeAdapter<Integer> {

  @Override
  public void write(JsonWriter out, Integer value) throws IOException {
    out.value(Integer.toHexString(value));
  }

  @Override
  public Integer read(JsonReader in) throws IOException {
    String base16String = in.nextString();
    return Integer.parseInt(base16String, 16);
  }

}
