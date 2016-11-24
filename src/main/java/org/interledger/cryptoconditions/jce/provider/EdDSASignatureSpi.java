package org.interledger.cryptoconditions.jce.provider;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import net.i2p.crypto.eddsa.EdDSAEngine;

public class EdDSASignatureSpi extends SignatureSpi {

  private EdDSAEngine engine = new EdDSAEngine();

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    engine.initVerify(publicKey);
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    engine.initSign(privateKey);
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    engine.update(b);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    engine.update(b, off, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    return engine.sign();
  }

  @Override
  protected boolean engineVerify(byte[] signature) throws SignatureException {
    return engine.verify(signature);
  }

  @Override
  protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    throw new InvalidParameterException("Parameters not supported.");
  }

  @Override
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new InvalidParameterException("Parameters not supported.");
  }
}
