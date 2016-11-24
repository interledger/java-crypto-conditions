package org.interledger.cryptoconditions.jce.provider.keys;

import org.interledger.cryptoconditions.jce.interfaces.DigestPrivateKey;

public class Sha256DigestPrivateKey implements DigestPrivateKey {

  private static final long serialVersionUID = 2381503462729025847L;
  private byte[] preimage;

  public Sha256DigestPrivateKey(byte[] preimage) {
    this.preimage = preimage.clone();
  }

  @Override
  public byte[] getPreimage() {
    return this.preimage.clone();
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
    return this.preimage.clone();
  }

}
