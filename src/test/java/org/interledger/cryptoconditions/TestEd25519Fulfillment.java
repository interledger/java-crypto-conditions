package org.interledger.cryptoconditions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.interledger.cryptoconditions.oer.FulfillmentOerInputStream;
import org.interledger.cryptoconditions.oer.OerDecodingException;
import org.junit.Test;

import net.i2p.crypto.eddsa.Utils;

// TODO:(0) Complete tests
public class TestEd25519Fulfillment {

  final byte[] TEST_SEED =
      Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
  static final byte[] TEST_PK =
      Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
  static final byte[] TEST_MSG = "This is a secret message".getBytes(Charset.forName("UTF-8"));
  static final byte[] TEST_INPUT_STREAM_FF_OK = Utils.hexToBytes(
      "000462203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da294094825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");
  static final byte[] TEST_INPUT_STREAM_FF_WRONG = Utils.hexToBytes(
      "000462203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da294094825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a1111111");

  static final byte[] TEST_KO_MSG =
      "This is a wrong secret message".getBytes(Charset.forName("UTF-8"));
  static final byte[] TEST_MSG_SIG = Utils.hexToBytes(
      "94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");
  static final byte[] TEST_KO_MSG_SIG = Utils.hexToBytes(
      "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");

  static final String FF_OK_URI =
      "cf:4:IDtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdopQJSCWJbHB1wxvLgfBtuivc2dzxbnkojUufh8JIIVyEaNR19Cnz3jtKLPZ_4XB3rhloYCA2TW1Pp6AXS6tKEjug8";

  private Fulfillment getPayload(byte[] ffOEREncoded)
      throws IOException, UnsupportedConditionException, OerDecodingException,
      NoSuchAlgorithmException, InvalidKeySpecException, IllegalFulfillmentException {
    ByteArrayInputStream auxi = new ByteArrayInputStream(ffOEREncoded);
    FulfillmentOerInputStream ffOut = new FulfillmentOerInputStream(auxi);
    Fulfillment result = ffOut.readFulfillment();

    ffOut.close();
    return result;
  }

  @Test
  public void testEd25519Fulfillment()
      throws IOException, UnsupportedConditionException, OerDecodingException,
      NoSuchAlgorithmException, InvalidKeySpecException, IllegalFulfillmentException {
    // Build from stream
    System.out.println("testEd25519Fulfillment start:");
    Fulfillment ff_ok = getPayload(TEST_INPUT_STREAM_FF_OK);
    // assertTrue(FF_OK_URI.equals(ff_ok.toURI()));
    // ff_ok.computeCondition();
    // assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(TEST_MSG));
    // assertFalse("Fulfillment validates TEST_KO_MSG", ff_ok.validate(TEST_KO_MSG));

    // Fulfillment ff_wrong = getPayload(TEST_INPUT_STREAM_FF_WRONG);
    // ff_wrong.computeCondition();
    // assertFalse("Fulfillment does not validates TEST_MSG", ff_wrong.validate(TEST_MSG));
    // assertFalse("Fulfillment does not validates TEST_KO_MSG", ff_wrong.validate(TEST_KO_MSG));

    // Build from URI
    // ff_ok = FulfillmentFactory.getFulfillmentFromURI(FF_OK_URI);
    // assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));

    // Build from secret
    // ff_ok =
    // Ed25519FulfillmentImpl.fromPrivateKeyAndMessage(Ed25519Signature.getPrivateKeyFromBytes(TEST_SEED),
    // TEST_MSG);
    // ff_ok.computeCondition();
    // assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(TEST_MSG));
    //
    // ff_ok =
    // Ed25519FulfillmentImpl.fromPrivateKeyAndMessage(Ed25519Signature.getPrivateKeyFromBytes(TEST_SEED),
    // TEST_KO_MSG);
    // ff_ok.computeCondition();
    // assertFalse("Fulfillment validates TEST_MSG", ff_ok.validate(TEST_MSG));

  }

}
