package org.interledger.cryptoconditions;

import org.junit.Test;

// TODO:(0) Complete tests
public class TestPrefixSha256Fulfillment {

  @Test
  public void testCreateFromPrefixAndSubfulfillment() {
    // String preimage = "616263";
    // Fulfillment PreimageSubff = PreimageSha256Fulfillment.fromPreimage(preimage.getBytes());
    // byte[] prefix = {1, 2, 3, 4};
    // PrefixSha256FulfillmentImpl ffPrefix =
    // PrefixSha256FulfillmentImpl.fromPrefixAndFulfillment(prefix, PreimageSubff);
    // TODO:(?) Improve this test.

    // String output = new String(((PreimageSha256Fulfillment)
    // ffPrefix.getSubFulfillment()).getPayload().payload);
    // assertTrue("preimage.equals(output)", preimage.equals(output));
  }

  @Test
  public void testCreatePrefixSha256FromURI() {
    // System.out.println("testCreatePrefixSha256FromURI");
    // // "Copy&Paste" from five-bells-conditions prefixSha256FulfillmentSpec.js
    // final String subffURI = "cf:0:" /* emptySha256 */,
    // prefix = "",
    // expectedPrefixffURI = "cf:1:AAAAAA",
    // expectedPrefixffCondURI = "cc:1:7:Yja3qFj7NS_VwwE7aJjPJos-uFCzStJlJLD4VsNy2XM:1";
    //
    // Fulfillment subff = FulfillmentFactory.getFulfillmentFromURI(subffURI);
    // PrefixSha256FulfillmentImpl prefixff =
    // PrefixSha256FulfillmentImpl.fromPrefixAndFulfillment(prefix.getBytes(), subff);
    // System.out.println("debug: expectedPrefixffURI:"+expectedPrefixffURI);
    // System.out.println("debug: prefixff.toURI():"+prefixff.toURI());
    // assertTrue(expectedPrefixffURI.equals(prefixff.toURI()));
    // System.out.println(expectedPrefixffCondURI);
    // System.out.println(prefixff.getCondition().toURI());
    // assertTrue(expectedPrefixffCondURI.equals(prefixff.getCondition().toURI()));
  }

}
