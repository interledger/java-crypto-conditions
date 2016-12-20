package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

public class RsaSha256Fulfillment implements Fulfillment {

  private RsaSha256Condition condition;
  private RSAPublicKey publicKey;
  private byte[] signature;
  
  public RsaSha256Fulfillment(RSAPublicKey publicKey, byte[] signature) {
    this.signature = new byte[signature.length];
    System.arraycopy(signature, 0, this.signature, 0, signature.length);
    this.publicKey = publicKey;
  }
  
  @Override
  public ConditionType getType() {
    return ConditionType.RSA_SHA256;
  }

  @Override
  public byte[] getEncoded() {
    try {
      //Build preimage sequence
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DEROutputStream out = new DEROutputStream(baos);
      out.writeTaggedObject(0, UnsignedBigInteger.toUnsignedByteArray(publicKey.getModulus()));
      out.writeTaggedObject(1, signature);
      out.close();
      byte[] buffer = baos.toByteArray();

      //Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.SEQUENCE.getTag(),
          buffer);
      out.close();
      
      //Wrap CHOICE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(
          DERTags.CONSTRUCTED.getTag() + 
          DERTags.TAGGED.getTag() + 
          getType().getTypeCode(),
          buffer
      );
      out.close();
      
      return baos.toByteArray();
      
    } catch (IOException e) {
      throw new RuntimeException("DER Encoding Error", e);
    }
  }

  @Override
  public RsaSha256Condition getCondition() {
    if(condition == null) {
      condition = new RsaSha256Condition(publicKey);
    }
    return condition;
  }

  @Override
  public boolean verify(Condition condition, byte[] message) {
    
    if(condition == null) {
      throw new IllegalArgumentException("Can't verify a RsaSha256Fulfillment against an null condition.");
    }
    
    if(!(condition instanceof RsaSha256Condition)) {
      throw new IllegalArgumentException("Must verify a RsaSha256Fulfillment against RsaSha256Condition.");
    }

    if(!getCondition().equals(condition)) {
      return false;
    }
    
    try {
      Signature rsaSigner = Signature.getInstance("SHA256withRSA/PSS");
      rsaSigner.initVerify(publicKey);
      rsaSigner.update(message);
      return rsaSigner.verify(signature);
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      // TODO Log error or throw?
      e.printStackTrace();
      return false;
    }
    
  }

}
