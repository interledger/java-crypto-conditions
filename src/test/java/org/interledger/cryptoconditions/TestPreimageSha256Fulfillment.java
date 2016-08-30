package org.interledger.cryptoconditions;


import static org.junit.Assert.*;

import org.junit.Test;


import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.types.*;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
// TODO:(0) Complete tests
public class TestPreimageSha256Fulfillment {

    @Test
    public void testCreate() {
        String[][] testData = {
                {"cf:0:AA", "cc:0:3:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0:1"},
                {"cf:0:"  , "cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0"},
        };

        String inputURI = testData[0][0];
        FulfillmentPayload ffPayload = new FulfillmentPayload(inputURI.getBytes());
        Fulfillment ff = new PreimageSha256Fulfillment(ConditionType.PREIMAGE_SHA256, ffPayload);
System.out.println("deleteme inputURI:"+inputURI + ", ff.toURI():"+ff.toURI());
        assertTrue("inputURI.equals(ff.toURI())", inputURI.equals(ff.toURI()) );
        
    }
}
