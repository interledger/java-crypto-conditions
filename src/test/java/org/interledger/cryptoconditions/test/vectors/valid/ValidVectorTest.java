package org.interledger.cryptoconditions.test.vectors.valid;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableList.Builder;
import com.google.common.io.BaseEncoding;
import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.HexDump;
import org.interledger.cryptoconditions.UnsignedBigInteger;
import org.interledger.cryptoconditions.der.CryptoConditionReader;
import org.interledger.cryptoconditions.der.DerEncodingException;
import org.interledger.cryptoconditions.test.CryptoConditionAssert;
import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.test.types.TestVectorConditionFactory;
import org.interledger.cryptoconditions.test.vectors.TestVector;
import org.interledger.cryptoconditions.test.vectors.TestVectorJson;
import org.interledger.cryptoconditions.types.Ed25519Sha256Fulfillment;
import org.interledger.cryptoconditions.types.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.types.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.types.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.types.ThresholdSha256Fulfillment;
import org.interledger.cryptoconditions.uri.CryptoConditionUri;
import org.interledger.cryptoconditions.uri.UriEncodingException;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * This class tests the Java implementation of crypto-conditions based on a set of pre-computed and
 * validated test vectors found in the crypto-conditions spec repository.
 *
 * Specifically, this harness performs the following validations  according to the source of the
 * test 'vectors' file in the crypto-conditions rfc project:
 *
 *
 * valid - These are examples of valid crypto-conditions and their fulfillments. You should run the
 * following tests against these:
 *
 * Parse conditionBinary, serialize as a URI, should match conditionUri.
 * Parse conditionUri, serialize as binary, should match conditionBinary.
 * Parse fulfillment, serialize fulfillment, should match fulfillment.
 * Parse fulfillment and validate, should return true.
 * Parse fulfillment and generate the fingerprint contents
 * Parse fulfillment, generate the condition, serialize the condition as a URI, should match
 * conditionUri.
 * Create fulfillment from json, serialize fulfillment, should match fulfillment.
 * If a message field is provided, the condition should be evaluated against the message. Otherwise,
 * an empty message should be passed to the verification function.
 *
 * invalid - These are examples of intrinsically invalid fulfillments, such as an invalid signature
 * or an encoding error.
 *
 * Parse fulfillment and validate, should return error.
 *
 *
 * // - parse the conditionBinary content, serializing as a uri and comparing to conditionUri
 * // - parse conditionUri, serialize to binary, and compare to conditionBinary
 * // TODO:
 * // - Parse fulfillment, serialize fulfillment, should match fulfillment.
 * // - Parse fulfillment and validate, should return true.
 * // - Parse fulfillment and generate the fingerprint contents
 * // - Parse fulfillment, generate the condition, serialize the condition as a URI, should match
 * // conditionUri.
 * // - Create fulfillment from json, serialize fulfillment, should match fulfillment.
 *
 * @see "https://github.com/rfcs/crypto-conditions/tree/master/test-vectors/valid"
 */
@RunWith(Parameterized.class)
public class ValidVectorTest {

  /**
   * Need to add BouncyCastle so we have a provider that supports SHA256withRSA/PSS signatures
   */
  static {
    Provider bc = new BouncyCastleProvider();
    Security.addProvider(bc);
  }

  private TestVector testVector;

  public ValidVectorTest(TestVector testVector) throws Exception {
    this.testVector = testVector;
  }

  /**
   * Loads a list of tests based on the json-encoded test vector files.
   */
  @Parameters(name = "Test Vector {index}: {0}")
  public static Collection<TestVector> testVectors() throws Exception {

    final URL classUri =
        ValidVectorTest.class.getResource(ValidVectorTest.class.getSimpleName() + ".class");
    final File dir = new File(classUri.toURI()).getParentFile();

    final Builder<TestVector> vectors = ImmutableList.builder();
    final ObjectMapper mapper = new ObjectMapper();

    Arrays.stream(dir.listFiles()).forEach(file -> {
      try {
        if (file.getName().endsWith(".json")) {
          TestVector vector = mapper.readValue(file, TestVector.class);
          vector.setName(file.getName().substring(0, file.getName().length() - 5));
          vectors.add(vector);
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });

    return vectors.build();
  }

  ////////////////
  // "Valid" Tests
  ////////////////

  //These are examples of valid crypto-conditions and their fulfillments.

  /**
   * This test parses the conditionBinary, serializes it as a URI, and validates that the generated
   * URI matches "conditionUri" from the test vector.
   */
  @Test
  public void testParseConditionBinary() throws DerEncodingException {
    final Condition actualCondition = CryptoConditionReader
        .readCondition(BaseEncoding.base16().decode(testVector.getConditionBinary()));
    final Condition testVectorCondition =
        TestVectorConditionFactory.getTestVectorCondition(testVector.getJson());

    assertThat(actualCondition.getUri().toString(), is(testVectorCondition.getUri().toString()));
    assertThat(actualCondition, is(testVectorCondition));
  }

  /**
   * This test parses a condition URI, serializes the condition to ASN.1 DER encoded bytes, and then
   * validates that the binary value matche the "conditionBinary" value from the test vector.
   */
  @Test
  public void testParseConditionFromUri() throws DerEncodingException, UriEncodingException {
    final Condition actualCondition = CryptoConditionUri
        .parse(URI.create(testVector.getConditionUri()));
    final byte[] actualEncodedCondition = actualCondition.getEncoded();

    final byte[] testVectorBinary = BaseEncoding.base16().decode(testVector.getConditionBinary());

    assertThat(actualEncodedCondition, is(testVectorBinary));
  }

  /**
   * This test parses a fulfillment from testVectors.fulfillment, serializes it to binary, and
   * asserts that the generated bytes match the serialized bytes.
   */
  @Test
  public void testParseFulfillmentBytes() throws DerEncodingException {
    final byte[] testVectorFulfillmentBytes = BaseEncoding.base16()
        .decode(testVector.getFulfillment());
    final Fulfillment testVectorFulfillment = CryptoConditionReader.readFulfillment(
        testVectorFulfillmentBytes
    );

    assertThat(testVectorFulfillment.getEncoded(), is(testVectorFulfillmentBytes));
  }

  /**
   * Parse fulfillment and validate, should return true.
   *
   * This test parses fulfillment from testVectors' condition URI. .fulfillment binary, serializes
   * it back to binary,
   * and then asserts that the generated bytes match the originally read bytes.
   */
  @Test
  public void testParseFulfillmentFromBinaryAndVerify()
      throws Exception {

    final Condition conditionFromTestVectorUri = CryptoConditionUri
        .parse(URI.create(testVector.getConditionUri()));
    final byte[] messageBytes = BaseEncoding.base16().decode(testVector.getMessage());

    final Fulfillment controlFulfillment = CryptoConditionReader
        .readFulfillment(BaseEncoding.base16().decode(testVector.getFulfillment()));

    assertThat(controlFulfillment.verify(conditionFromTestVectorUri, messageBytes), is(true));

    ///////////
    // DELETE AFTER THIS

    // So PublicKey in fulfillment1 (created directly with correct public key) is different from
    // Fulfillment2 (read from binary, but has wrong public key)

//    final byte[] messageBytes = BaseEncoding.base16().decode(testVector.getMessage());
//
//    Condition condition = CryptoConditionReader
//        .readCondition(BaseEncoding.base16().decode(testVector.getConditionBinary()));
//
//    byte[] modulusBytes = Base64.getUrlDecoder().decode(testVector.getJson().getModulus());
//    final BigInteger modulus = UnsignedBigInteger.fromUnsignedByteArray(modulusBytes);
//    final BigInteger exponent = BigInteger.valueOf(65537);
//    final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
//
//    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//    final RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(spec);
//
//    byte[] signature = BaseEncoding.base64Url().decode(testVector.getJson().getSignature());
//
//    final RsaSha256Fulfillment fulfillment1 = new RsaSha256Fulfillment(pubKey, signature);
//    final Fulfillment fulfillment2 = CryptoConditionReader
//        .readFulfillment(BaseEncoding.base16().decode(testVector.getFulfillment()));
//
//    fulfillment2.verify(condition, messageBytes);
  }

  /**
   * This test parses a fulfillment from testVectors.fulfillment and validates that this value
   * matches the fingerprint from an actual Condition generated from the testVector JSON.
   */
  @Test
  public void testParseFulfillmentFromBinaryAndValidateFingerprintContents() {
    final byte[] testVectorFingerprint = BaseEncoding.base16()
        .decode(testVector.getFingerprintContents());

    final TestCondition actualTestCondition = TestVectorConditionFactory
        .getTestVectorCondition(testVector.getJson());

    assertThat(actualTestCondition.getUnhashedFingerprint(), is(testVectorFingerprint));
  }

  /**
   * This test parses the fulfillment from the test vector file, generate the condition, serializes
   * the condition as a URI, and validates that the generated URI matches the conditionUri.
   *
   * @throws DerEncodingException
   * @throws UriEncodingException
   */
  @Test
  public void testParseFulfillmentFromBinaryAndGenerateCondition()
      throws DerEncodingException, UriEncodingException {

    final Fulfillment testVectorFulfillment = CryptoConditionReader
        .readFulfillment(BaseEncoding.base16().decode(testVector.getFulfillment()));

    final String derivedUri = testVectorFulfillment.getCondition().getUri().toString();

    assertThat(testVector.getConditionUri(), is(derivedUri));
  }

  /**
   * This create a fulfillment from json, serializes the fulfillment, and then checks to ensure that
   * the serialized fulfillment matches json.fulfillment.
   */
  @Test
  @Ignore
  public void testParseJsonFulfillment() throws Exception {
    // Used to recursively assemble subfulfillments if they exist in the JSON test vector file.
    final Fulfillment controlFulfillment = CryptoConditionReader
        .readFulfillment(BaseEncoding.base16().decode(testVector.getFulfillment()));

    final String encodedControlFulfillment = BaseEncoding.base64Url()
        .encode(controlFulfillment.getEncoded());

    final Fulfillment fulfillmentFromJson = this.getFulfillmentFromJson(testVector.getJson());
    final String encodedFulfillmentFromJson = BaseEncoding.base64Url()
        .encode(fulfillmentFromJson.getEncoded());

    assertThat(encodedControlFulfillment, is(encodedFulfillmentFromJson));
  }

  @Test
  public void testCost() throws UriEncodingException, DerEncodingException {
    final long actualCost = TestVectorConditionFactory.getTestVectorCondition(testVector.getJson())
        .getCost();

    assertThat(actualCost, is(testVector.getCost()));
  }

  @Test
  public void testParseFulfillmentAndCheckProperties() throws Exception {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    Fulfillment fulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);

    switch (fulfillment.getType()) {
      case PREIMAGE_SHA256:
        PreimageSha256Fulfillment preimageFulfillment = (PreimageSha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare preimage]",
            Base64.getUrlDecoder().decode(testVector.getJson().getPreimage()),
            preimageFulfillment.getPreimage());
        break;

      case PREFIX_SHA256:
        PrefixSha256Fulfillment prefixFulfillment = (PrefixSha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare prefix]",
            Base64.getUrlDecoder().decode(testVector.getJson().getPrefix()),
            prefixFulfillment.getPrefix());
        assertEquals(testVector.getName() + " [compare max message length]",
            testVector.getJson().getMaxMessageLength(), prefixFulfillment.getMaxMessageLength());
        CryptoConditionAssert.assertSetOfTypesIsEqual(testVector.getName() + " [compare subtypes]",
            testVector.getSubtypes(), prefixFulfillment.getCondition().getSubtypes());

        // TODO Should we test for equality of subfulfillments?
        break;

      case THRESHOLD_SHA256:
        ThresholdSha256Fulfillment thresholdFulfillment = (ThresholdSha256Fulfillment) fulfillment;
        assertEquals(testVector.getName() + " [compare threshold]",
            testVector.getJson().getThreshold(), thresholdFulfillment.getThreshold());
        CryptoConditionAssert.assertSetOfTypesIsEqual(testVector.getName() + " [compare subtypes]",
            testVector.getSubtypes(), thresholdFulfillment.getCondition().getSubtypes());
        // TODO Should we test for equality of subfulfillments and subconditions?
        break;

      case RSA_SHA256:
        RsaSha256Fulfillment rsaFulfillment = (RsaSha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare rsa key modulus]",
            Base64.getUrlDecoder().decode(testVector.getJson().getModulus()),
            UnsignedBigInteger.toUnsignedByteArray(rsaFulfillment.getPublicKey().getModulus()));
        assertArrayEquals(testVector.getName() + " [compare rsa signature]",
            Base64.getUrlDecoder().decode(testVector.getJson().getSignature()),
            rsaFulfillment.getSignature());
        break;

      case ED25519_SHA256:
        Ed25519Sha256Fulfillment ed25519Fulfillment = (Ed25519Sha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare ed25519 key]",
            Base64.getUrlDecoder().decode(testVector.getJson().getPublicKey()),
            ed25519Fulfillment.getPublicKey().getAbyte());
        assertArrayEquals(testVector.getName() + " [compare signature]",
            Base64.getUrlDecoder().decode(testVector.getJson().getSignature()),
            ed25519Fulfillment.getSignature());
        break;

      default:
        throw new Exception("Unknown fulfillment type: " + fulfillment.getType());
    }
  }

  /**
   * Assembles an instance of {@link Fulfillment} from the information provided in an instance of
   * {@link TestVectorJson}, which is ultimately assembled from a JSON file in this test harness.
   */
  private Fulfillment getFulfillmentFromJson(final TestVectorJson testVectorJson) throws Exception {
    Objects.requireNonNull(testVectorJson);

    // final TestVectorJson testVectorJson = testVector.getJson();

    switch (testVectorJson.getType()) {

      case "preimage-sha-256": {
        return new PreimageSha256Fulfillment(
            BaseEncoding.base64Url().decode(testVectorJson.getPreimage())
        );
      }

      case "prefix-sha-256": {
        return new PrefixSha256Fulfillment(
            BaseEncoding.base64Url().decode(testVectorJson.getPrefix()),
            testVectorJson.getMaxMessageLength(),
            getFulfillmentFromJson(testVectorJson.getSubfulfillment())
        );
      }

      case "threshold-sha-256": {
        final Set<Fulfillment> subFulfillments = Arrays
            .stream(testVectorJson.getSubfulfillments())
            .map(subfulfillment -> {
                  try {
                    return getFulfillmentFromJson(subfulfillment);
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                }
            )
            .collect(Collectors.toSet());

        final Set<Condition> subConditions = subFulfillments.stream()
            .map(Fulfillment::getCondition)
            .collect(Collectors.toSet());

        return new ThresholdSha256Fulfillment(
            subConditions.toArray(new Condition[]{}),
            subFulfillments.toArray(new Fulfillment[]{})
        );
      }

      case "rsa-sha-256": {
        final BigInteger modulus = new BigInteger(
            BaseEncoding.base64Url().decode(testVectorJson.getModulus()));
        final byte[] rsaSignature = BaseEncoding.base64Url().decode(testVectorJson.getSignature());
        final RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(modulus,
            RsaSha256Fulfillment.PUBLIC_EXPONENT);

        try {
          final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
          final PublicKey publicKey = rsaKeyFactory.generatePublic(rsaSpec);
          return new RsaSha256Fulfillment((RSAPublicKey) publicKey, rsaSignature);
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }

      case "ed25519-sha-256": {
        final EdDSANamedCurveSpec params = EdDSANamedCurveTable.getByName("Ed25519");
        final EdDSAPublicKeySpec keyspec = new EdDSAPublicKeySpec(
            BaseEncoding.base64Url().decode(testVectorJson.getPublicKey()),
            params
        );
        final EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(keyspec.getA(), params);
        return new Ed25519Sha256Fulfillment(
            new EdDSAPublicKey(pubKeySpec),
            BaseEncoding.base64Url().decode(testVectorJson.getSignature())
        );
      }

      default: {
        throw new RuntimeException(String.format("Unhandled Type %s", testVectorJson.getType()));
      }
    }
  }

  /**
   * Assembles an instance of {@link Fulfillment} from the information provided in an instance of
   * {@link TestVectorJson}, which is ultimately assembled from a JSON file in this test harness.
   */
//  private Condition getConditionFromJson(final TestVectorJson testVectorJson) throws Exception {
//    Objects.requireNonNull(testVectorJson);
//
//    switch (testVectorJson.getType()) {
//
//      case "preimage-sha-256": {
//        return new PreimageSha256Condition(
//            BaseEncoding.base64Url().decode(testVectorJson.getPreimage())
//        );
//      }
//
//      case "prefix-sha-256": {
//        return new PrefixSha256Condition(
//            BaseEncoding.base64Url().decode(testVectorJson.getPrefix()),
//            testVectorJson.getMaxMessageLength(),
//            getConditionFromJson(testVectorJson.getSubfulfillment())
//        );
//      }
//
//      case "threshold-sha-256": {
//        final List<Fulfillment> subFulfillments = Arrays
//            .stream(testVectorJson.getSubfulfillments())
//            .map(subfulfillment -> {
//                  try {
//                    return getFulfillmentFromJson(subfulfillment);
//                  } catch (Exception e) {
//                    throw new RuntimeException(e);
//                  }
//                }
//            )
//            .collect(Collectors.toList());
//
//        final List<Condition> subConditions = subFulfillments.stream()
//            .map(Fulfillment::getCondition)
//            .collect(Collectors.toList());
//
//        return new ThresholdSha256Condition(
//            testVectorJson.getThreshold(),
//            subConditions.toArray(new Condition[0])
//        );
//      }
//
//      case "rsa-sha-256": {
//        final BigInteger modulus = new BigInteger(
//            BaseEncoding.base64Url().decode(testVectorJson.getModulus()));
//        byte[] rsaSignature = BaseEncoding.base64Url().decode(testVectorJson.getSignature());
//        final RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(modulus,
//            RsaSha256Fulfillment.PUBLIC_EXPONENT);
//
//        try {
//          final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
//          final PublicKey publicKey = rsaKeyFactory.generatePublic(rsaSpec);
//          return new RsaSha256Fulfillment(
//              (RSAPublicKey) publicKey,
//              rsaSignature
//          ).getCondition();
//        } catch (Exception e) {
//          throw new RuntimeException(e);
//        }
//      }
//
//      case "ed25519-sha-256": {
//        final EdDSANamedCurveSpec params = EdDSANamedCurveTable.getByName("Ed25519");
//        final EdDSAPublicKeySpec keyspec = new EdDSAPublicKeySpec(
//            BaseEncoding.base64Url().decode(testVectorJson.getPublicKey()),
//            params
//        );
//        final EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(keyspec.getA(), params);
//
//        return new Ed25519Sha256Fulfillment(
//            new EdDSAPublicKey(pubKeySpec),
//            BaseEncoding.base64Url().decode(testVectorJson.getSignature())
//        ).getCondition();
//      }
//
//      default: {
//        throw new RuntimeException(String.format("Unhandled Type %s", testVectorJson.getType()));
//      }
//    }
//  }
}