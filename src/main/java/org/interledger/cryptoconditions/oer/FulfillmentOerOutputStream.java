package org.interledger.cryptoconditions.oer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Ed25519Fulfillment;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.IllegalFulfillmentException;
import org.interledger.cryptoconditions.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.util.UnsignedBigInteger;

/**
 * Writes an OER encoded fulfillment to a stream.
 *
 * Limitations: - Only supports the compiled condition type codes (up to 4) - Assumes payload length
 * of less than 16777215 bytes
 *
 * @author adrianhopebailie
 */
public class FulfillmentOerOutputStream extends OerOutputStream {

  public FulfillmentOerOutputStream(OutputStream stream) {
    super(stream);
  }

  /**
   * Write the fulfillment to the underlying stream using OER encoding per the specification:
   * 
   * Fulfillment ::= SEQUENCE { type ConditionType, payload OCTET STRING }
   * 
   * ConditionType ::= INTEGER { preimageSha256(0), rsaSha256(1), prefixSha256(2),
   * thresholdSha256(3), ed25519(4) } (0..65535)
   * 
   * @param fulfillment
   * @throws IOException
   * @throws IllegalFulfillmentException
   */
  public void writeFulfillment(Fulfillment fulfillment)
      throws IOException, IllegalFulfillmentException {
    writeConditionType(fulfillment.getType());
    switch (fulfillment.getType()) {

      case PREIMAGE_SHA256:
        writePreimageSha256FulfillmentPayload((PreimageSha256Fulfillment) fulfillment);
        break;

      case PREFIX_SHA256:
        writePrefixSha256FulfillmentPayload((PrefixSha256Fulfillment) fulfillment);
        break;

      case RSA_SHA256:
        writeRsaSha256FulfillmentPayload((RsaSha256Fulfillment) fulfillment);
        break;

      case ED25519:
        writeEd25519FulfillmentPayload((Ed25519Fulfillment) fulfillment);
        break;

      case THRESHOLD_SHA256:
        // TODO writeThresholdSha256FulfillmentPayload;
      default:
        throw new RuntimeException("Unimplemented fulfillment type encountered.");
    }

  }

  public void writeConditionType(ConditionType type) throws IOException {
    write16BitUInt(type.getTypeCode());
  }

  protected void writePayload(byte[] payload) throws IOException {
    writeOctetString(payload);
  }

  public void writePreimageSha256FulfillmentPayload(PreimageSha256Fulfillment fulfillment)
      throws IOException {
    writeOctetString(fulfillment.getPreimage());
  }

  public void writePrefixSha256FulfillmentPayload(PrefixSha256Fulfillment fulfillment)
      throws IOException, IllegalFulfillmentException {

    PayloadOutputStream substream = new PayloadOutputStream();
    substream.writeOctetString(fulfillment.getPrefix());
    substream.writeFulfillment(fulfillment.getSubfulfillment());
    writeOctetString(substream.getBytes());
    substream.close();
  }

  public void writeRsaSha256FulfillmentPayload(RsaSha256Fulfillment fulfillment)
      throws IOException, IllegalFulfillmentException {

    BigInteger modulus = fulfillment.getModulus();
    byte[] modulusBytes = UnsignedBigInteger.toUnsignedByteArray(modulus);

    if (modulusBytes.length < RsaSha256Fulfillment.MINIMUM_MODULUS_SIZE)
      throw new IllegalFulfillmentException("Modulus size cannot be smaller than "
          + RsaSha256Fulfillment.MINIMUM_MODULUS_SIZE + " bytes.");

    if (modulusBytes.length > RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE)
      throw new IllegalFulfillmentException("Modulus size cannot be larger than "
          + RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE + " bytes.");

    byte[] signatureBytes = fulfillment.getSignature();

    if (signatureBytes.length < RsaSha256Fulfillment.MINIMUM_MODULUS_SIZE)
      throw new IllegalFulfillmentException("Signature size cannot be smaller than "
          + RsaSha256Fulfillment.MINIMUM_SIGNATURE_SIZE + " bytes.");

    if (signatureBytes.length > RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE)
      throw new IllegalFulfillmentException("Signature size cannot be larger than "
          + RsaSha256Fulfillment.MAXIMUM_SIGNATURE_SIZE + " bytes.");

    if (modulusBytes.length != signatureBytes.length)
      throw new IllegalFulfillmentException("Modulus and signature must be the same size.");

    BigInteger signature = UnsignedBigInteger.fromUnsignedByteArray(signatureBytes);

    if (modulus.compareTo(signature) <= 0)
      throw new IllegalFulfillmentException("Signature must be numerically smaller than modulus.");

    PayloadOutputStream substream = new PayloadOutputStream();
    substream.writeOctetString(modulusBytes);
    substream.writeOctetString(signatureBytes);
    writeOctetString(substream.getBytes());
    substream.close();
  }

  public void writeEd25519FulfillmentPayload(Ed25519Fulfillment fulfillment)
      throws IOException, IllegalFulfillmentException {

    byte[] encodedKey = fulfillment.getPublicKey();
    if (encodedKey.length != Ed25519Fulfillment.PUBKEY_LENGTH)
      throw new IllegalFulfillmentException("Key length (" + encodedKey.length + ")"
          + " is not the expected value (" + Ed25519Fulfillment.PUBKEY_LENGTH + ").");

    if (fulfillment.getSignature().length != Ed25519Fulfillment.SIGNATURE_LENGTH)
      throw new IllegalArgumentException("Signature length (" + fulfillment.getSignature().length
          + ")" + " is not the expected value (" + Ed25519Fulfillment.SIGNATURE_LENGTH + ")");

    PayloadOutputStream substream = new PayloadOutputStream();
    substream.writeOctetString(encodedKey, true);
    substream.writeOctetString(fulfillment.getSignature(), true);
    writeOctetString(substream.getBytes());
    substream.close();

  }

  private class PayloadOutputStream extends FulfillmentOerOutputStream {

    public PayloadOutputStream() {
      super(new ByteArrayOutputStream());
    }

    public byte[] getBytes() throws IOException {
      return ((ByteArrayOutputStream) stream).toByteArray();
    }
  }
}
