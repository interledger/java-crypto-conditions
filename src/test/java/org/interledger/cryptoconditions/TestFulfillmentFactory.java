package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import org.junit.Test;

import org.interledger.cryptoconditions.FulfillmentFactory;

public class TestFulfillmentFactory {

	@Test
	public void testCreateFromURI() {
		String fulfillmentSha256 = "cf:0:AA";
		
		Fulfillment ff = FulfillmentFactory.getFulfillmentFromURI(fulfillmentSha256);
System.out.println(fulfillmentSha256 + " equals " +ff.toURI());
		assertTrue(fulfillmentSha256 + "equals " +ff.toURI(), fulfillmentSha256.equals(ff.toURI()));
	}


}
