package org.interledger.cryptoconditions;

import java.util.Arrays;
import java.util.EnumSet;



import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAEngine;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class Ed25519Fulfillment extends FulfillmentBase {
    
    public static final int PUBKEY_LENGTH = 32; 
    public static final int SIGNATURE_LENGTH = 64; 
    public static final int FULFILLMENT_LENGTH = PUBKEY_LENGTH + SIGNATURE_LENGTH;

    private final byte[] publicKey;
    private final byte[] signature;
    private final byte[] message;
    
    private byte[] privateKey = null;

    public Ed25519Fulfillment(ConditionType type, byte[] payload) {
        super(type, payload);
        // TODO:(0) Test implementation correct.
        if (payload.length != FULFILLMENT_LENGTH) throw new
            RuntimeException("payload length ("+payload.length+")"
                + " doesn't match Ed25519 fulfillment length ("+FULFILLMENT_LENGTH+")");
        this.publicKey = Arrays.copyOfRange(payload, 0, Ed25519Fulfillment.PUBKEY_LENGTH);
        this.message   = new byte[]{}; // TODO:(0)
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

        if (this.privateKey == null ) throw 
            new RuntimeException("this.privateKey not yet defined ");
        EnumSet<FeatureSuite> features = EnumSet.of(FeatureSuite.ED25519); // TODO:(0) Recheck

        // TODO:(0) Must be ed25519.sign(privateKey, message).
        // TODO:(0) we can't set privateKey before calling the constructor.
         
        
        PrivateKey sKey = new EdDSAPrivateKey(
                new EdDSAPrivateKeySpec(
                        this.privateKey, EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512)));
        try {
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initSign(sKey);
            sgr.update(this.message);
            byte[] signature = null; // TODO:(0)
            return new ConditionImpl(
                    ConditionType.ED25519, 
                    features,
                    signature, 
                    FULFILLMENT_LENGTH);
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    // setPublicKey (publicKey /*Ed25519 public key */) {
    //     if (publicKey.length !== 32) throw new Error('Public key must be 32 bytes, was: ' + publicKey.length);
    //     // TODO Validate public key
    //     this.publicKey = publicKey
    //   }
    // 
    //   /** Instead of using the private key to sign using the sign() method, we can
    //    * also generate the signature elsewhere and pass it in. */
    //   setSignature (signature /* 64-byte signature */) {
    //     if (signature.length !== 64) throw new Error('Signature must be 64 bytes, was: ' + signature.length)
    //     this.signature = signature
    //   }

    @Override
    public boolean validate(byte[] message) {
        if (privateKey == null ) {
            throw new RuntimeException("privateKey is undefined. Validation can't continue");
        }

        /**
           * Verify the signature of this Ed25519 fulfillment.
           *
           * The signature of this Ed25519 fulfillment is verified against the provided
           * message and public key.
           *
           */
        //    if (ed25519) {
        //      result = ed25519.Verify(message, this.signature, this.publicKey)
        //    }

        throw new RuntimeException("Not implemented");

    }
}
