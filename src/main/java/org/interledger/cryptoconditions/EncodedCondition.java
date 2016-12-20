package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.util.Base64;

import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

public abstract class EncodedCondition implements Condition {
  
  public byte[] getEncoded() {
    try {
      //Build Fingerprint and Cost SEQUENCE
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DEROutputStream out = new DEROutputStream(baos);
      out.writeOctetString(getFingerprint());
      out.writeInteger(BigInteger.valueOf(getCost()));
      if(this instanceof CompoundCondition) {
        byte[] bitStringData = ConditionType.getEnumOfTypesAsBitString(((CompoundCondition)this).getSubtypes());
        out.writeBitString(bitStringData);
      }
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
      buffer = baos.toByteArray();
      
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
      throw new RuntimeException("DER Encoding Error.", e);
    }
  }
  
  public URI getURI() {
    
    StringBuilder sb = new StringBuilder();
    sb.append("ni://")
      .append("/sha-256;")
      .append(Base64.getUrlEncoder().withoutPadding().encodeToString(getFingerprint()))
      .append("?")
      .append("fht=").append(getType().toString().toLowerCase())
      .append("&cost=").append(getCost());
      
    if(this instanceof CompoundCondition) {
      sb.append("&subtypes=").append(ConditionType.getEnumOfTypesAsString(((CompoundCondition)this).getSubtypes()));
    }
      
    return URI.create(sb.toString());
  }

  @Override
  public String toString() {
    return getURI().toString();
  }
      
}
