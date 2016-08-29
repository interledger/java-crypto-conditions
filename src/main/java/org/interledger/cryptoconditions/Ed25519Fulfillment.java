package org.interledger.cryptoconditions;

import java.util.Arrays;
import java.util.EnumSet;



//import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;


import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSAEngine;

// TODO:(0) Add dependencies in ed25519 external library.
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author earizon<enrique.arizon.benito@everis.com>
 *
 */

public class Ed25519Fulfillment extends FulfillmentBase {
    // TODO:(?) Create utility classes to generate public/private keys
	//     for example for a site that just one a one-time-use public/private key.
    public static final int PUBKEY_LENGTH = 32; 
    public static final int SIGNATURE_LENGTH = 64; 
    public static final int FULFILLMENT_LENGTH = PUBKEY_LENGTH + SIGNATURE_LENGTH;

    private final byte[] publicKey;
    private final byte[] signature;
    
    private byte[] privateKey = null;

    public Ed25519Fulfillment(ConditionType type, byte[] payload) {
        super(type, payload);
        // TODO:(0) Test implementation correct.
        if (payload.length != FULFILLMENT_LENGTH) throw new
            RuntimeException("payload length ("+payload.length+")"
                + " doesn't match Ed25519 fulfillment length ("+FULFILLMENT_LENGTH+")");
        /*
         * REF: https://interledger.org/five-bells-condition/spec.html#rfc.section.4.5.2
         * Ed25519FulfillmentPayload ::= SEQUENCE {
         *     publicKey OCTET STRING (SIZE(32)),
         *     signature OCTET STRING (SIZE(64))
         * }
         */
        this.publicKey = Arrays.copyOfRange(payload, 0, Ed25519Fulfillment.PUBKEY_LENGTH);
        this.signature = Arrays.copyOfRange(payload, Ed25519Fulfillment.PUBKEY_LENGTH, Ed25519Fulfillment.SIGNATURE_LENGTH);
    }

    @Override
    public ConditionType getType() {
        return ConditionType.ED25519;
    }

    @Override
    public byte[] getPayload() 
    {
        return payload.clone();
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }
    @Override
    public Condition generateCondition(byte[] payload) 
    {
        // TODO:(0) This will fail now since generateCondition is invoqued in the
        // constructor before setPrivateKey is invoqued.

        if (this.privateKey == null ) {
        	// TODO:(0) This will fail now. generateCondition is called before privateKey is set
            throw new RuntimeException("this.privateKey not yet defined ");
        }
        EnumSet<FeatureSuite> features = EnumSet.of(FeatureSuite.ED25519); // TODO:(0) Recheck

         
        
        PrivateKey sKey = new EdDSAPrivateKey(
                new EdDSAPrivateKeySpec(
                        this.privateKey, EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512)));
        try {
            return new ConditionImpl(
                    ConditionType.ED25519, 
                    features,
                    this.publicKey, 
                    FULFILLMENT_LENGTH);
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    @Override
    public boolean validate(byte[] message) {
        if (this.publicKey == null ) {
            throw new RuntimeException("privateKey is undefined. Validation can't continue");
        }
        if (this.signature == null ) {
            throw new RuntimeException("privateKey is undefined. Validation can't continue");
        }
        try{
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
            
            EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(publicKey, spec);
            PublicKey vKey = new EdDSAPublicKey(pubKey);
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initVerify(vKey);
            sgr.update(message);
            return sgr.verify(signature);
    	}catch(Exception e){
    		throw new RuntimeException(e.toString(), e);
    	}
    }
}
