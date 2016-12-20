package org.interledger.cryptoconditions;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

public class Application {

  public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, InvalidKeyException, SignatureException {
    
    Provider bc = new BouncyCastleProvider();
    System.out.println(bc.getInfo());
    Security.addProvider(bc);

    byte[] preimage = "Hello World!".getBytes(Charset.defaultCharset());
    byte[] prefix = "Ying ".getBytes(Charset.defaultCharset());
    byte[] message = "Yang".getBytes(Charset.defaultCharset());
    byte[] prefixedMessage = "Ying Yang".getBytes(Charset.defaultCharset());
    
    MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
    MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
    
    byte[] fingerprint = sha256Digest.digest(preimage);
    
    KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
    rsaKpg.initialize(new RSAKeyGenParameterSpec(2048, new BigInteger("65537")));
    KeyPair rsaKeyPair = rsaKpg.generateKeyPair();
    Signature rsaSigner = Signature.getInstance("SHA256withRSA/PSS");
    rsaSigner.initSign(rsaKeyPair.getPrivate());
    rsaSigner.update(message);
    byte[] rsaSignature = rsaSigner.sign();
    
    net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
    KeyPair edDsaKeyPair = edDsaKpg.generateKeyPair();
    Signature edDsaSigner = new EdDSAEngine(sha512Digest);
    edDsaSigner.initSign(edDsaKeyPair.getPrivate());
    edDsaSigner.update(prefix);
    edDsaSigner.update(message);
    byte[] edDsaSignature = edDsaSigner.sign();

    PreimageSha256Condition preimageCondition = new PreimageSha256Condition(preimage);
    RsaSha256Condition rsaCondition = new RsaSha256Condition((RSAPublicKey) rsaKeyPair.getPublic());
    Ed25519Sha256Condition ed25519Condition = new Ed25519Sha256Condition((EdDSAPublicKey) edDsaKeyPair.getPublic());
    PrefixSha256Condition prefixConditionOnEd25519Condition = new PrefixSha256Condition(prefix, 1000, ed25519Condition);
    ThresholdSha256Condition thresholdCondition = new ThresholdSha256Condition(2, new Condition[]{
       preimageCondition, rsaCondition, prefixConditionOnEd25519Condition 
    });
    
    PreimageSha256Fulfillment preimageFulfillment = new PreimageSha256Fulfillment(preimage);    
    RsaSha256Fulfillment rsaFulfillment = new RsaSha256Fulfillment((RSAPublicKey) rsaKeyPair.getPublic(), rsaSignature);
    Ed25519Sha256Fulfillment ed25519Fulfillment = new Ed25519Sha256Fulfillment((EdDSAPublicKey) edDsaKeyPair.getPublic(), edDsaSignature);
    PrefixSha256Fulfillment prefixFulfillmentOnEd25519Fulfillment = new PrefixSha256Fulfillment(prefix, 1000, ed25519Fulfillment);
    ThresholdSha256Fulfillment thresholdFulfillment = new ThresholdSha256Fulfillment(
        new Condition[]{rsaCondition},
        new Fulfillment[]{preimageFulfillment, prefixFulfillmentOnEd25519Fulfillment});
    
    hexDump("preimage", preimage);
    hexDump("prefix", prefix);
    hexDump("message", message);
    hexDump("fingerprint", fingerprint);
    hexDump("rsa_privatekey", rsaKeyPair.getPrivate().getEncoded());
    hexDump("rsa_publickey", rsaKeyPair.getPublic().getEncoded());
    hexDump("rsa_sig", rsaSignature);
    hexDump("eddsa_privatekey", edDsaKeyPair.getPrivate().getEncoded());
    hexDump("eddsa_publickey", edDsaKeyPair.getPublic().getEncoded());
    hexDump("eddsa_sig", edDsaSignature);
    
    hexDump("preimage_condition", preimageCondition.getEncoded());
    System.out.println("preimage_condition: " + preimageCondition.toString());
    hexDump("ed25519_condition", ed25519Condition.getEncoded());
    System.out.println("ed25519_condition: " + ed25519Condition.toString());
    hexDump("rsa_condition", rsaCondition.getEncoded());
    System.out.println("rsa_condition: " + rsaCondition.toString());
    hexDump("prefix_condition", prefixConditionOnEd25519Condition.getEncoded());
    System.out.println("prefix_condition: " + prefixConditionOnEd25519Condition.toString());
    hexDump("threshold_condition", thresholdCondition.getEncoded());
    System.out.println("threshold_condition: " + thresholdCondition.toString());
    
    hexDump("preimage_fulfillment", preimageFulfillment.getEncoded());
    hexDump("ed25519_fulfillment", ed25519Fulfillment.getEncoded());
    hexDump("rsa_fulfillment", rsaFulfillment.getEncoded());
    hexDump("prefix_fulfillment", prefixFulfillmentOnEd25519Fulfillment.getEncoded());
    hexDump("threshold_fulfillment", thresholdFulfillment.getEncoded());

    System.out.println("preimage : " + (preimageFulfillment.verify(preimageCondition, message) ? "VERIFIED" : "FAILED"));
    System.out.println("rsa : " + (rsaFulfillment.verify(rsaCondition, message) ? "VERIFIED" : "FAILED"));
    System.out.println("ed25519 : " + (ed25519Fulfillment.verify(ed25519Condition, prefixedMessage) ? "VERIFIED" : "FAILED"));
    System.out.println("prefix on ed25519 : " + (prefixFulfillmentOnEd25519Fulfillment.verify(prefixConditionOnEd25519Condition, message) ? "VERIFIED" : "FAILED"));
    System.out.println("threshold : " + (thresholdFulfillment.verify(thresholdCondition, message) ? "VERIFIED" : "FAILED"));
    
/*    
    System.out.println(" 00 01 : " + new BigInteger(new byte[]{0x00, 0x01}).toString());
    System.out.println(" 00 80 : " + new BigInteger(new byte[]{0x00, (byte) 0x80}).toString());
    System.out.println(" 80 FF : " + new BigInteger(new byte[]{(byte) 0x80, (byte) 0xFF}).toString());
    System.out.println(" 80 01 : " + new BigInteger(new byte[]{(byte) 0x80, (byte) 0x01}).toString());
    System.out.println(" 80 : " + new BigInteger(new byte[]{(byte) 0x80}).toString());
    System.out.println(" FF : " + new BigInteger(new byte[]{(byte) 0xFF}).toString());
    
    System.out.println("Base64Url of fingerprint: " + Base64.getUrlEncoder().withoutPadding().encodeToString(fingerprint));
*/ 
  }
  
  private static void hexDump(String label, byte[] bytes) {
    System.out.print("<" + label + ">");
    System.out.println(HexDump.dumpHexString(bytes));
    System.out.println("</" + label + ">");
  }

}
