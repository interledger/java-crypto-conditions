package org.interledger.cryptoconditions.jce.interfaces;

import java.security.PublicKey;

public interface DigestPublicKey extends PublicKey {

  byte[] getDigest();

}
