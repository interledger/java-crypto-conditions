package org.interledger.cryptoconditions.json;

import java.io.IOException;

import org.interledger.cryptoconditions.util.Base16;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

public class ByteArrayBase16TypeAdaptor extends TypeAdapter<byte[]> {

  @Override
  public void write(JsonWriter out, byte[] value) throws IOException {
    out.value(Base16.encode(value));
  }

  @Override
  public byte[] read(JsonReader in) throws IOException {
    String base16String = in.nextString();
    return Base16.decode(base16String);
  }

}
