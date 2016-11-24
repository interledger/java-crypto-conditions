package org.interledger.cryptoconditions.uri;

import java.io.IOException;
import java.io.Writer;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.oer.FeatureSuiteOerEncoding;

public class ConditionWriter extends Writer {

  private static char[] HEADER = new char[] {'c', 'c'};
  private static char[] VERSION = new char[] {'0', '1'};
  private static char DELIMITER = ':';

  private Writer writer;

  public ConditionWriter(Writer innerWriter) {
    this.writer = innerWriter;
  }

  /**
   * Write the condition to the underlying writer using String encoding
   * 
   * @param condition
   * @throws IOException
   */
  public void writeCondition(Condition condition) throws IOException {
    writeHeader();
    writeDelimiter();
    writeConditionType(condition.getType());
    writeDelimiter();
    writeFeatures(condition.getFeatures());
    writeDelimiter();
    writeFingerprint(condition.getFingerprint());
    writeDelimiter();
    writeMaxFulfillmentLength(condition.getMaxFulfillmentLength());

  }

  protected void writeDelimiter() throws IOException {
    writer.write(DELIMITER);
  }

  protected void writeHeader() throws IOException {
    writer.write(HEADER);
  }

  protected void writeVersion() throws IOException {
    writer.write(VERSION);
  }

  protected void writeConditionType(ConditionType type) throws IOException {
    writer.write(Integer.toString(type.getTypeCode(), 16));
  }


  protected void writeFeatures(EnumSet<FeatureSuite> features) throws IOException {
    int bitmask = FeatureSuiteOerEncoding.getBitmaskFromFeatures(features);
    writer.write(Integer.toString(bitmask, 16));
  }

  protected void writeFingerprint(byte[] fingerprint) throws IOException {

    writer.write(Hex.encode(fingerprint));
  }

  protected void writeMaxFulfillmentLength(int maxFulfillmentLength) throws IOException {

    writer.write(Integer.toString(maxFulfillmentLength));
  }


  @Override
  public void write(char[] cbuf, int off, int len) throws IOException {
    writer.write(cbuf, off, len);
  }

  @Override
  public void flush() throws IOException {
    writer.flush();
  }

  @Override
  public void close() throws IOException {
    writer.close();
  }

  private static class Hex {
    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String encode(byte[] bytes) {
      char[] hexChars = new char[bytes.length * 2];
      for (int j = 0; j < bytes.length; j++) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = hexArray[v >>> 4];
        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
      }
      return new String(hexChars);
    }
  }

  public static char[] getHeader() {
    return HEADER;
  }

  public static char[] getVersion() {
    return VERSION;
  }

  public static char getDelimiter() {
    return DELIMITER;
  }
}
