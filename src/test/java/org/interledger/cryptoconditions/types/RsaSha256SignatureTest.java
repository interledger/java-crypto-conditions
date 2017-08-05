package org.interledger.cryptoconditions.types;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableList.Builder;
import com.google.common.io.BaseEncoding;
import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.interledger.cryptoconditions.types.helpers.RsaTestVectorJson;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class RsaSha256SignatureTest extends AbstractCryptoConditionTest {

  /**
   * Need to add BouncyCastle so we have a provider that supports SHA256withRSA/PSS signatures
   */
  static {
    Provider bc = new BouncyCastleProvider();
    Security.addProvider(bc);
  }

  private final KeyFactory keyFactory;
  private final Signature rsaSigner;
  private final RsaTestVectorJson rsaJsonTestVector;

  public RsaSha256SignatureTest(final RsaTestVectorPair testVectorPair) throws Exception {
    Objects.requireNonNull(testVectorPair);
    this.keyFactory = KeyFactory.getInstance("RSA");
    this.rsaSigner = testVectorPair.getSignature();
    this.rsaJsonTestVector = testVectorPair.getRsaTestVectorJson();
  }

  /**
   * Loads a list of tests based on the json-encoded test vector files. Each object in the array
   */
  @Parameters(name = "Modulus {index}: {0}")
  public static Collection<RsaTestVectorPair> testVectors() throws Exception {

    final URL classUri = RsaSha256SignatureTest.class
        .getResource(RsaSha256SignatureTest.class.getSimpleName() + ".class");
    final File dir = new File(classUri.toURI()).getParentFile();

    final Builder<RsaTestVectorPair> vectors = ImmutableList.builder();
    final ObjectMapper mapper = new ObjectMapper();

    final Signature rsaSha256Signer = Signature.getInstance("SHA256withRSA/PSS", "BC");
    Arrays.stream(dir.listFiles()).forEach(file -> {
      try {
        if (file.getName().endsWith("sha256.json")) {
          final List<RsaTestVectorJson> testVectors = mapper
              .readValue(file, new TypeReference<List<RsaTestVectorJson>>() {
              });

          vectors.addAll(
              testVectors.stream()
                  .map(tv -> new RsaTestVectorPair(rsaSha256Signer, tv))
                  .collect(Collectors.toList()));
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });

    final Signature rsaSha1Signer = Signature.getInstance("SHA1withRSA/PSS", "BC");
    Arrays.stream(dir.listFiles()).forEach(file -> {
      try {

        if (file.getName().endsWith("sha1.json")) {
          final List<RsaTestVectorJson> testVectors = mapper
              .readValue(file, new TypeReference<List<RsaTestVectorJson>>() {
              });

          vectors.addAll(
              testVectors.stream()
                  .map(tv -> new RsaTestVectorPair(rsaSha1Signer, tv))
                  .collect(Collectors.toList()));
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });

    return vectors.build();
  }

  /**
   * This test ensures that the supplied private key signs a message correctly.
   */
  @Test
  public void testSignsCorrectly() throws Exception {

    final String privKeyPEM = rsaJsonTestVector.getPrivateKey();
    final RSAPrivateKey privKey = this.buildRsaPrivKey(privKeyPEM);

    rsaJsonTestVector.getCases().stream().forEach(_case -> {
      try {
        final byte[] saltHex = BaseEncoding.base16().decode(_case.getSalt().toUpperCase());
        rsaSigner.initSign(privKey, new FixedRandom(saltHex));
        rsaSigner.update(BaseEncoding.base16().decode(_case.getMessage().toUpperCase()));
        byte[] rsaSignature = rsaSigner.sign();

        assertThat(_case.getSignature().toUpperCase(),
            is(BaseEncoding.base16().encode(rsaSignature)));
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });
  }

  /**
   * This test ensures that the supplied private key signs a message correctly.
   */
  @Test
  public void testVerifiesCorrectly()
      throws Exception {

    final String privKeyPEM = rsaJsonTestVector.getPrivateKey();
    final RSAPrivateKey privKey = this.buildRsaPrivKey(privKeyPEM);

    rsaJsonTestVector.getCases().stream().forEach(_case -> {
      try {
        final byte[] saltHex = BaseEncoding.base16().decode(_case.getSalt().toUpperCase());
        rsaSigner.initSign(privKey, new FixedRandom(saltHex));
        rsaSigner.update(BaseEncoding.base16().decode(_case.getMessage().toUpperCase()));

        final byte[] expectedSignatureBytes = BaseEncoding.base16()
            .decode(_case.getSignature().toUpperCase());

        final byte[] actualSignatureByte = rsaSigner.sign();
        assertThat(actualSignatureByte, is(expectedSignatureBytes));

      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });
  }

  private RSAPrivateKey buildRsaPrivKey(String privateKeyString) throws Exception {
    final byte[] innerKey = BaseEncoding.base64()
        .decode(privateKeyString.replaceAll("-----\\w+ RSA PRIVATE KEY-----", ""));
    final byte[] result = new byte[innerKey.length + 26];
    System
        .arraycopy(BaseEncoding.base64().decode("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKY="), 0, result,
            0, 26);
    System.arraycopy(BigInteger.valueOf(result.length - 4).toByteArray(), 0, result, 2, 2);
    System.arraycopy(BigInteger.valueOf(innerKey.length).toByteArray(), 0, result, 24, 2);
    System.arraycopy(innerKey, 0, result, 26, innerKey.length);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(result);
    return (RSAPrivateKey) this.keyFactory.generatePrivate(spec);
  }

  /**
   * Helper method to construct an instance of {@link KeyPair} containing keys for testing purposes.
   *
   * @return An instance of {@link KeyPair}.
   */
//  protected KeyPair constructRsaKeyPair()
//      throws NoSuchAlgorithmException, InvalidKeySpecException {
//    byte[] modulusBytes = Base64.getUrlDecoder().decode(this.rsaJsonTestVector.getModulus());
//    final BigInteger modulus = UnsignedBigInteger.fromUnsignedByteArray(modulusBytes);
//    final BigInteger exponent = BigInteger.valueOf(65537);
//    final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
//
//    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//
//    return new KeyPair(keyFactory.generatePublic(spec), keyFactory.generatePrivate(spec));
//  }

  private class FixedRandom extends SecureRandom {

    byte[] vals;

    FixedRandom(byte[] vals) {
      this.vals = vals;
    }

    public void nextBytes(byte[] bytes) {
      System.arraycopy(vals, 0, bytes, 0, vals.length);
    }
  }

  private static class RsaTestVectorPair {

    private final Signature signature;
    private final RsaTestVectorJson rsaTestVectorJson;

    private RsaTestVectorPair(final Signature signature,
        final RsaTestVectorJson rsaTestVectorJson) {
      this.signature = Objects.requireNonNull(signature);
      this.rsaTestVectorJson = Objects.requireNonNull(rsaTestVectorJson);
    }

    public Signature getSignature() {
      return signature;
    }

    public RsaTestVectorJson getRsaTestVectorJson() {
      return rsaTestVectorJson;
    }
  }
}
