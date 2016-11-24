package org.interledger.cryptoconditions.jce.provider;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Arrays;

import org.interledger.cryptoconditions.jce.interfaces.DigestPrivateKey;
import org.interledger.cryptoconditions.jce.interfaces.DigestPublicKey;

public class Sha256DigestSignatureSpi extends SignatureSpi {

  private byte[] digest = null;
  private byte[] preimage = null;
  private MessageDigest internalDigest = null;


  public Sha256DigestSignatureSpi() {

  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof DigestPublicKey)) {
      throw new InvalidKeyException("Supplied key is not a Digest.");
    }
    this.digest = ((DigestPublicKey) publicKey).getDigest();
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (!(privateKey instanceof DigestPrivateKey)) {
      throw new InvalidKeyException("Supplied key is not a Preimage.");
    }
    this.preimage = ((DigestPrivateKey) privateKey).getPreimage();
    try {
      internalDigest = MessageDigest.getInstance(((DigestPrivateKey) privateKey).getAlgorithm());
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidKeyException(e);
    }
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    // No op
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    // No op
  }

  @Override
  protected byte[] engineSign() throws SignatureException {

    if (this.preimage == null) {
      throw new SignatureException("Signature is not initialized.");
    }

    return internalDigest.digest(preimage);

  }

  @Override
  protected boolean engineVerify(byte[] signature) throws SignatureException {

    if (this.digest == null) {
      throw new SignatureException("Signature is not initialized.");
    }
    return Arrays.equals(digest, signature);
  }

  @Override
  protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    throw new InvalidParameterException("Digest signatures take no parameters.");
  }

  @Override
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new InvalidParameterException("Digest signatures take no parameters.");
  }

}
