package org.interledger.cryptoconditions.test.types;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.UnsignedBigInteger;
import org.interledger.cryptoconditions.test.vectors.TestVectorJson;
import org.interledger.cryptoconditions.types.CryptoConditionReader;
import org.interledger.cryptoconditions.types.Ed25519Sha256Condition;
import org.interledger.cryptoconditions.types.PrefixSha256Condition;
import org.interledger.cryptoconditions.types.PreimageSha256Condition;
import org.interledger.cryptoconditions.types.RsaSha256Condition;
import org.interledger.cryptoconditions.types.ThresholdSha256Condition;

/**
 * Builds instances of {@link Condition} for testing based on the test vectors loaded.
 */
public class TestVectorConditionFactory {

  /**
   * Constructs a condition based on the test vector JSON file.
   */
  public static Condition getTestVectorCondition(final TestVectorJson condition) {
    Objects.requireNonNull(condition);

    final ConditionType type = ConditionType.fromString(condition.getType());

    switch (type) {

      case PREIMAGE_SHA256: {
        return new PreimageSha256Condition(
            Base64.getUrlDecoder().decode(condition.getPreimage()));
      }

      case PREFIX_SHA256: {
        return new PrefixSha256Condition(Base64.getUrlDecoder().decode(condition.getPrefix()),
            condition.getMaxMessageLength(),
            getTestVectorCondition(condition.getSubfulfillment()));
      }

      case THRESHOLD_SHA256: {
        List<Condition> subconditions = new ArrayList<>();
        for (TestVectorJson vector : condition.getSubfulfillments()) {
          subconditions.add(getTestVectorCondition(vector));
        }
        return new ThresholdSha256Condition(
            condition.getThreshold(),
            subconditions.toArray(new Condition[subconditions.size()])
        );
      }

      case RSA_SHA256: {
        byte[] modulusBytes = Base64.getUrlDecoder().decode(condition.getModulus());
        BigInteger modulus = UnsignedBigInteger.fromUnsignedByteArray(modulusBytes);
        BigInteger exponent = BigInteger.valueOf(65537);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        try {
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
          return new RsaSha256Condition(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
          throw new RuntimeException("Error creating RSA key.", e);
        }
      }

      case ED25519_SHA256: {
        byte[] publicKeyBytes = Base64.getUrlDecoder().decode(condition.getPublicKey());

        final EdDSAPublicKeySpec publicKeyspec = new EdDSAPublicKeySpec(
            publicKeyBytes, EdDSANamedCurveTable.getByName(CryptoConditionReader.ED_25519)
        );
        final EdDSAPublicKey publicKey = new EdDSAPublicKey(publicKeyspec);
        return new Ed25519Sha256Condition(publicKey);
      }

      default:
        throw new RuntimeException(String.format("Unknown Condition type: %s", type));
    }

  }
}
