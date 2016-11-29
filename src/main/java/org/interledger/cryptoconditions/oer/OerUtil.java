package org.interledger.cryptoconditions.oer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.IllegalFulfillmentException;
import org.interledger.cryptoconditions.UnsupportedConditionException;

public class OerUtil {

  public static int MAX_INT = 16777215;

  public static byte[] getLengthPrefixedOctetString(byte[] input) {

    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    OerOutputStream stream = new OerOutputStream(buffer);

    try {
      stream.writeOctetString(input);
      stream.flush();
      return buffer.toByteArray();
    } catch(IOException e){
        throw new RuntimeException(e.toString(), e);
    } finally {
        try { stream.close(); }catch(IOException e) {/* can't fix in a close */}
    }
  }


  public static Condition getCondition(byte[] oerEncodedCondition)
      throws IOException, UnsupportedConditionException, OerDecodingException {

    ByteArrayInputStream buffer = new ByteArrayInputStream(oerEncodedCondition);
    ConditionOerInputStream stream = new ConditionOerInputStream(buffer);

    try {
      return stream.readCondition();
    } finally {
      stream.close();
    }

  }

  public static Fulfillment getFullfillment(byte[] oerEncodedFulfillment) throws IOException,
      UnsupportedConditionException, OerDecodingException, IllegalFulfillmentException {

    ByteArrayInputStream buffer = new ByteArrayInputStream(oerEncodedFulfillment);
    FulfillmentOerInputStream stream = new FulfillmentOerInputStream(buffer);

    try {
      return stream.readFulfillment();
    } finally {
      stream.close();
    }

  }

  /**
   * Convenience function for getting the binary encoding of a Fulfillment
   * 
   * @param condition
   * @return The OER encoded condition
   * @throws IOException
   */
  public static byte[] getOerEncodedCondition(Condition condition) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    ConditionOerOutputStream stream = new ConditionOerOutputStream(buffer);

    try {
      stream.writeCondition(condition);
      stream.flush();
    } finally {
      stream.close();
    }

    return buffer.toByteArray();
  }

  /**
   * Convenience function for getting the binary encoding of a Fulfillment
   * 
   * Hides the potential IllegalFulfillmentException behind a RuntimeException
   * 
   * @param fulfillment
   * @return The OER encoded fulfillment
   * @throws IllegalFulfillmentException
   * @throws IOException
   * @throws RuntimeException if the Fulfillment is not ready to be encoded.
   */
  public static byte[] getOerEncodedFulfillment(Fulfillment fulfillment)
      throws IOException, IllegalFulfillmentException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    FulfillmentOerOutputStream stream = new FulfillmentOerOutputStream(buffer);

    try {
      stream.writeFulfillment(fulfillment);
      stream.flush();
    } finally {
      stream.close();
    }

    return buffer.toByteArray();

  }
}
