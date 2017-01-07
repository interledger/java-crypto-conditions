package org.interledger.cryptoconditions.der;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.HexDump;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test the implementation of crypto-condition parsing from/to uri's and binary
 */
@RunWith(Parameterized.class)
public class Test_CryptoConditionReader {

  @Parameters
  public static Collection<String> testVectors() {
    return Arrays.asList(new String[] {
        "0000_test-minimal-preimage.json",
        "0001_test-minimal-prefix.json",
        "0002_test-minimal-threshold.json",
        "0003_test-minimal-rsa.json",
        "0004_test-minimal-ed25519.json",
        "0005_test-basic-preimage.json",
        "0006_test-basic-prefix.json",
        "0007_test-basic-prefix-two-levels-deep.json",
        "0008_test-basic-threshold.json",
        "0009_test-basic-threshold-same-condition-twice.json",
        "0010_test-basic-threshold-same-fulfillment-twice.json",
        "0011_test-basic-threshold-two-levels-deep.json",
        "0012_test-basic-threshold-schroedinger.json",
        "0013_test-basic-rsa.json",
        "0014_test-basic-rsa4096.json",
        "0015_test-basic-ed25519.json",
        "0016_test-advanced-notarized-receipt.json",
        "0017_test-advanced-notarized-receipt-multiple-notaries.json"});
  }
  
  private TestVector testVector;
  private String vectorName;
  
  public Test_CryptoConditionReader(String vectorName) throws Exception {
    this.vectorName = vectorName;
    
    ObjectMapper m = new ObjectMapper();
    try(InputStream is = getClass().getClassLoader().getResourceAsStream(vectorName)) {
        testVector = m.readValue(is, TestVector.class);
    }
  }
  
  @Test
  public void test() throws URIEncodingException, DEREncodingException {
    // according to the source of the test 'vectors' (https://github.com/rfcs/crypto-conditions),
    // we should test by
    // - parse the conditionBinary content, serializing as a uri and comparing to conditionUri
    // - parse conditionUri, serialize to binary, and compare to conditionBinary
    
    //test 1, binary ==> uri
    Condition binaryCondition = CryptoConditionReader.readCondition(HexDump.hexStringToByteArray(testVector.getConditionBinary()));
    assertEquals(vectorName + " [binary => uri]", testVector.getConditionUri(), binaryCondition.getUri().toString());
    
    //test 2, uri ==> binary
    Condition uriCondition = CryptoConditionReader.fromUri(URI.create(testVector.getConditionUri()));
    assertEquals(vectorName + " [uri => binary]", testVector.getConditionBinary(), HexDump.toHexString(uriCondition.getEncoded()));
  }
}

