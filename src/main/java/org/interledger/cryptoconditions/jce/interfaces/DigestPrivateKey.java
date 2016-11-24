package org.interledger.cryptoconditions.jce.interfaces;

import java.security.PrivateKey;

public interface DigestPrivateKey extends PrivateKey {

  byte[] getPreimage();

}
