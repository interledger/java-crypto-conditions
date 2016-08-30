package org.interledger.cryptoconditions;


import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import org.junit.Test;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.types.*;

// TODO:(0) Complete tests
public class TestPrefixSha256Fulfillment {

    @Test
    public void testCreate() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        
        assertTrue("XXX", false /* TODO */);
        
    }
}
