package org.interledger.cryptoconditions.oer;



import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Ed25519Fulfillment;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.IllegalFulfillmentException;
import org.interledger.cryptoconditions.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.UnsupportedLengthException;
import org.interledger.cryptoconditions.impl.Ed25519FulfillmentImpl;
import org.interledger.cryptoconditions.impl.PrefixSha256FulfillmentImpl;
import org.interledger.cryptoconditions.impl.PreimageSha256FulfillmentImpl;
import org.interledger.cryptoconditions.impl.RsaSha256FulfillmentImpl;
import org.interledger.cryptoconditions.util.UnsignedBigInteger;

/**
 * Reads and decodes Fulfillments from an underlying input stream.
 * 
 * Fulfillments are expected to be OER encoded on the stream
 * 
 * @see Fulfillment
 * @author adrianhopebailie
 *
 */
public class FulfillmentOerInputStream extends OerInputStream {

  public FulfillmentOerInputStream(InputStream stream) {
    super(stream);
  }

  /**
   * Read a fulfillment from the underlying stream using OER encoding per the specification:
   * 
   * Fulfillment ::= SEQUENCE { type ConditionType, payload OCTET STRING }
   * 
   * ConditionType ::= INTEGER { preimageSha256(0), rsaSha256(1), prefixSha256(2),
   * thresholdSha256(3), ed25519(4) } (0..65535)
   * 
   * @throws IOException
   * @throws OerDecodingException
   * @throws UnsupportedConditionException
   * @throws IllegalFulfillmentException
   * @throws InvalidKeySpecException
   * @throws NoSuchAlgorithmException
   */
  public Fulfillment readFulfillment() throws IOException, UnsupportedConditionException,
      OerDecodingException, IllegalFulfillmentException {
    ConditionType type = readConditiontype();
    switch (type) {
      case PREIMAGE_SHA256:
        return (Fulfillment)readPreimageSha256FulfillmentPayload();

      case PREFIX_SHA256:
        return (Fulfillment)readPrefixSha256FulfillmentPayload();

      case RSA_SHA256:
        return (Fulfillment)readRsaSha256FulfillmentPayload();

      case ED25519:
        return (Fulfillment)readEd25519FulfillmentPayload();

      case THRESHOLD_SHA256:
        // TODO return readThresholdSha256Fulfillment;
      default:
        throw new RuntimeException("Unimplemented fulfillment type encountered.");
    }

  }

  public PreimageSha256Fulfillment readPreimageSha256FulfillmentPayload()
      throws IOException, UnsupportedLengthException, IllegalOerLengthIndicatorException {

    PreimageSha256FulfillmentImpl fulfillment = new PreimageSha256FulfillmentImpl();

    fulfillment.setPreimage(readPayload());

    return fulfillment;
  }

  public PrefixSha256Fulfillment readPrefixSha256FulfillmentPayload() throws IOException,
      UnsupportedConditionException, OerDecodingException, IllegalFulfillmentException {

    PrefixSha256FulfillmentImpl fulfillment = new PrefixSha256FulfillmentImpl();

    // Read the length indicator off the stream
    readLengthIndicator();

    fulfillment.setPrefix(readOctetString());
    fulfillment.setSubfulfillment(readFulfillment());

    return fulfillment;

  }

  public RsaSha256Fulfillment readRsaSha256FulfillmentPayload() throws IOException,
      UnsupportedLengthException, IllegalOerLengthIndicatorException, IllegalFulfillmentException {

    RsaSha256FulfillmentImpl fulfillment = new RsaSha256FulfillmentImpl();

    // Read the length indicator off the stream
    readLengthIndicator();

    byte[] modulusBytes = readOctetString(RsaSha256Fulfillment.MINIMUM_MODULUS_SIZE,
        RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE);

    byte[] signatureBytes = readOctetString(RsaSha256Fulfillment.MINIMUM_SIGNATURE_SIZE,
        RsaSha256Fulfillment.MAXIMUM_SIGNATURE_SIZE);

    if (modulusBytes.length != signatureBytes.length)
      throw new IllegalFulfillmentException("Modulus and signature must be the same size.");

    BigInteger modulus = UnsignedBigInteger.fromUnsignedByteArray(modulusBytes);
    BigInteger signature = UnsignedBigInteger.fromUnsignedByteArray(signatureBytes);

    if (modulus.compareTo(signature) <= 0)
      throw new IllegalFulfillmentException("Signature must be numerically smaller than modulus.");

    fulfillment.setModulus(modulus);
    fulfillment.setSignature(signatureBytes);

    return fulfillment;

  }

  public Ed25519Fulfillment readEd25519FulfillmentPayload()
      throws IOException, UnsupportedLengthException, IllegalOerLengthIndicatorException {

    Ed25519FulfillmentImpl fulfillment = new Ed25519FulfillmentImpl();

    // Read the length indicator off the stream
    readLengthIndicator();

    fulfillment.setPublicKey(readOctetString(Ed25519Fulfillment.PUBKEY_LENGTH));
    fulfillment.setSignature(readOctetString(Ed25519Fulfillment.SIGNATURE_LENGTH));

    return fulfillment;

  }

  public ConditionType readConditiontype() throws IOException {
    int value = read16BitUInt();
    return ConditionType.valueOf(value);
  }

  protected byte[] readPayload()
      throws IOException, UnsupportedLengthException, IllegalOerLengthIndicatorException {

    return readOctetString();
  }

}
