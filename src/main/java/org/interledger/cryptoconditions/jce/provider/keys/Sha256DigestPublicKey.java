package org.interledger.cryptoconditions.jce.provider.keys;

import org.interledger.cryptoconditions.jce.interfaces.DigestPublicKey;

public class Sha256DigestPublicKey implements DigestPublicKey {

  private static final long serialVersionUID = -892894667149527660L;
  private byte[] digest;

  public Sha256DigestPublicKey(byte[] digest) {
    this.digest = digest.clone();
  }

  @Override
  public byte[] getDigest() {
    return this.digest.clone();
  }

  @Override
  public String getAlgorithm() {
    return "SHA-256";
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    return this.digest.clone();
  }

}
