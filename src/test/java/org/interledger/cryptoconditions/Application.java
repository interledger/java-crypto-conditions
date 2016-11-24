package org.interledger.cryptoconditions;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.interledger.cryptoconditions.jce.provider.InterledgerProvider;
import org.interledger.cryptoconditions.jce.provider.keys.Sha256DigestPrivateKey;
import org.interledger.cryptoconditions.jce.provider.keys.Sha256DigestPublicKey;
import org.interledger.cryptoconditions.jce.spec.OerEncodedFulfillmentKeySpec;
import org.interledger.cryptoconditions.json.JsonUtil;
import org.interledger.cryptoconditions.oer.OerUtil;

public class Application {

  public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException,
      SignatureException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException {
    
    Provider p = new InterledgerProvider();
    System.out.println(p.getInfo());
    Security.addProvider(p);

    Provider bc = new BouncyCastleProvider();
    System.out.println(bc.getInfo());
    Security.addProvider(bc);

    byte[] message = "Hello World!".getBytes(Charset.defaultCharset());

    hexDump("message", message);

    net.i2p.crypto.eddsa.KeyPairGenerator kpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
    KeyPair kp = kpg.generateKeyPair();

    hexDump("eddsa_privatekey", kp.getPrivate().getEncoded());

    hexDump("eddsa_publickey", kp.getPublic().getEncoded());

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    KeyPair digestKeypair = new KeyPair(new Sha256DigestPublicKey(digest.digest(message)),
        new Sha256DigestPrivateKey(message));

    KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
    rsaKpg.initialize(new RSAKeyGenParameterSpec(2048, new BigInteger("65537")));
    KeyPair rsaKeyPair = rsaKpg.generateKeyPair();
    AlgorithmParameterSpec pssParams =
        new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);

    hexDump("rsa_privatekey", rsaKeyPair.getPrivate().getEncoded());

    hexDump("rsa_publickey", rsaKeyPair.getPublic().getEncoded());

    testSignature("EdDSA", kp, p, message, null);

    testSignature("SHA256withNONE", digestKeypair, p, message, null);

    testSignature("SHA256withRSA", rsaKeyPair, null, message, null);

    testSignature("SHA256withRSA", rsaKeyPair, null, message, pssParams);

    testSignature("SHA256withRSA/PSS", rsaKeyPair, null, message, pssParams);

    testSignature("SHA256withRSA/PSS", rsaKeyPair, bc, message, null);

    testSignature("SHA256withRSA/PSS", rsaKeyPair, bc, message, pssParams);

    testFulfillment("PreimageSha256Fulfillment", digestKeypair, p, message);

    testFulfillment("RsaSha256Fulfillment", rsaKeyPair, p, message);

    testFulfillment("Ed25519Fulfillment", kp, p, message);

    // testSignature("PrefixSha256Fulfillment", p, message);
  }

  private static void testSignature(String algo, KeyPair kp, Provider p, byte[] message,
      AlgorithmParameterSpec params) throws NoSuchAlgorithmException, InvalidKeyException,
      SignatureException, InvalidAlgorithmParameterException {

    System.out.println("Testing: " + algo);
    Signature s;
    if (p != null) {
      s = Signature.getInstance(algo, p);
    } else {
      s = Signature.getInstance(algo);
    }
    System.out.println("Provider: " + s.getProvider().getName());

    if (params != null) {
      s.setParameter(params);
      if (params instanceof PSSParameterSpec) {
        PSSParameterSpec algoParams = (PSSParameterSpec) params;
        System.out.println("Params:");
        System.out.println("- digest: " + algoParams.getDigestAlgorithm());
        System.out.println("- mask: " + algoParams.getMGFAlgorithm());
        System.out.println("- mask digest: "
            + ((MGF1ParameterSpec) algoParams.getMGFParameters()).getDigestAlgorithm());
        System.out.println("- salt length: " + algoParams.getSaltLength());
        System.out.println("- trailer: " + algoParams.getTrailerField());
      }
    } else if ("SHA256withRSA/PSS".equals(algo)) {
      AlgorithmParameters algoParams = s.getParameters();
      System.out.println("Params: " + algoParams.toString());

      // System.out.println("Params:");
      // System.out.println("- digest: " + algoParams.getDigestAlgorithm());
      // System.out.println("- mask: " + algoParams.getMGFAlgorithm());
      // System.out.println("- mask digest: " +
      // ((MGF1ParameterSpec)algoParams.getMGFParameters()).getDigestAlgorithm());
      // System.out.println("- salt length: " + algoParams.getSaltLength());
      // System.out.println("- trailer: " + algoParams.getTrailerField());
    }



    s.initSign(kp.getPrivate());
    s.update(message);

    byte[] sig = s.sign();

    hexDump("signature", sig);

    s.initVerify(kp.getPublic());
    s.update(message);

    System.out.println(s.verify(sig) ? "Success" : "Fail");
  }

  private static void testFulfillment(String algo, KeyPair kp, Provider p, byte[] message)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
      InvalidKeySpecException, IOException {

    System.out.println("Testing: " + algo);
    Signature s;
    if (p != null) {
      s = Signature.getInstance(algo, p);
    } else {
      s = Signature.getInstance(algo);
    }
    System.out.println("Provider: " + s.getProvider().getName());

    s.initSign(kp.getPrivate());
    s.update(message);

    byte[] fulfillment = s.sign();

    hexDump("fulfillment", fulfillment);

    // Get Condition
    KeySpec fullfillmentKeySpec = new OerEncodedFulfillmentKeySpec(fulfillment);
    KeyFactory kf = KeyFactory.getInstance("CryptoConditions");

    PublicKey condition = kf.generatePublic(fullfillmentKeySpec);

    if (condition.getEncoded() != null)
      hexDump("condition", condition.getEncoded());
    else
      hexDump("condition", OerUtil.getOerEncodedCondition((Condition) condition));

    System.out.println(JsonUtil.toJson((Condition) condition));

    s.initVerify(condition);
    s.update(message);

    System.out.println(s.verify(fulfillment) ? "Success" : "Fail");
  }

  private static void hexDump(String label, byte[] bytes) {
    System.out.print("<" + label + ">");
    System.out.println(HexDump.dumpHexString(bytes));
    System.out.println("</" + label + ">");
  }
}
