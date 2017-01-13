package org.interledger.cryptoconditions.test.vectors.valid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.HexDump;
import org.interledger.cryptoconditions.der.CryptoConditionReader;
import org.interledger.cryptoconditions.der.DEREncodingException;
import org.interledger.cryptoconditions.test.TestVector;
import org.interledger.cryptoconditions.uri.CryptoConditionUri;
import org.interledger.cryptoconditions.uri.URIEncodingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test the implementation of crypto-condition parsing from/to uri's and binary
 */
@RunWith(Parameterized.class)
public class Test_ValidTestVectors {
  
  @Parameters
  public static Collection<TestVector> testVectors() throws URISyntaxException, JsonParseException, JsonMappingException, IOException {
    
    ObjectMapper m = new ObjectMapper();
    URL classUri = Test_ValidTestVectors.class.getResource("Test_ValidTestVectors.class");
    File dir = new File(classUri.toURI()).getParentFile();

    List<TestVector> vectors = new ArrayList<>();
    
    for (File file : dir.listFiles()) {
      if(file.getName().endsWith(".json")) {
        TestVector vector = m.readValue(file, TestVector.class);
        vector.setName(file.getName().substring(0, file.getName().length() - 5));
        vectors.add(vector);
      }
    }
    return vectors;
    
  }
  
  private TestVector testVector;
  
  public Test_ValidTestVectors(TestVector testVector) throws Exception {
    this.testVector = testVector;
  }
  
  // according to the source of the test 'vectors' (https://github.com/rfcs/crypto-conditions),
  // we should test by
  // - parse the conditionBinary content, serializing as a uri and comparing to conditionUri
  // - parse conditionUri, serialize to binary, and compare to conditionBinary
  // TODO:
  // - Parse fulfillment, serialize fulfillment, should match fulfillment.
  // - Parse fulfillment and validate, should return true.
  // - Parse fulfillment and generate the fingerprint contents
  // - Parse fulfillment, generate the condition, serialize the condition as a URI, should match conditionUri.
  // - Create fulfillment from json, serialize fulfillment, should match fulfillment.
  
  @Test
  public void testParseConditionAndGenerateUri() throws URIEncodingException, DEREncodingException {
    
    Condition binaryCondition = CryptoConditionReader.readCondition(HexDump.hexStringToByteArray(testVector.getConditionBinary()));
    assertEquals(testVector.getName() + " [binary condition => uri]", URI.create(testVector.getConditionUri()), binaryCondition.getUri());
    
  }
  
  @Test
  public void testParseConditionUriAndGenerateBinary() throws URIEncodingException {
    
    Condition uriCondition = CryptoConditionUri.parse(URI.create(testVector.getConditionUri()));
    assertEquals(testVector.getName() + " [condition uri => binary]", testVector.getConditionBinary(), HexDump.toHexString(uriCondition.getEncoded()));
    
  }
  
  @Test
  public void testParseFulfillmentAndReserialize() throws URIEncodingException, DEREncodingException {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    Fulfillment binaryFulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);
    assertArrayEquals(testVector.getName() + " [fulfillment deserialize/reserialize]", fulfillmentBytes, binaryFulfillment.getEncoded());    
  }
  
  @Test
  public void testParseFulfillmentAndValidate() throws URIEncodingException, DEREncodingException {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    byte[] message = (testVector.getMessage() != null) ? HexDump.hexStringToByteArray(testVector.getMessage()) : new byte[]{};
    
    Fulfillment fulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);
    Condition condition = CryptoConditionUri.parse(URI.create(testVector.getConditionUri()));

    assertTrue(testVector.getName() + " [fulfillment validate]", fulfillment.verify(condition, message));    
  }
  
  
  
  
}

