package org.interledger.cryptoconditions.uri;

import java.io.IOException;
import java.io.Reader;

import org.interledger.cryptoconditions.Condition;

public class ConditionUriReader extends Reader {

  private Reader stream;

  public Condition ReadCondition() {
    return null;
    // TODO Implement

  }

  @Override
  public void close() throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public int read(char[] cbuf, int off, int len) throws IOException {
    return stream.read(cbuf, off, len);
  }

}
