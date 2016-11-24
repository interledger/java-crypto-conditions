package org.interledger.cryptoconditions.jce.provider;

import java.security.KeyFactorySpi;
import java.security.Provider;
import java.security.SignatureSpi;

public final class InterledgerProvider extends Provider {

  private static final long serialVersionUID = -3465230972149561201L;
  public static final String PROVIDER_NAME = "INTERLEDGER";
  public static final double PROVIDER_VERSION = 0.1;
  public static final String PROVIDER_INFO = "Interledger Crypto-Conditions Security Provider v0.1";

  public InterledgerProvider() {
    super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

    putSignature("EdDSA", EdDSASignatureSpi.class);
    putSignature("SHA256withNONE", Sha256DigestSignatureSpi.class);
    putSignature("PreimageSha256Fulfillment", PreimageSha256FulfillmentSignatureSpi.class);
    putSignature("RsaSha256Fulfillment", RsaSha256FulfillmentSignatureSpi.class);
    putSignature("Ed25519Fulfillment", Ed25519FulfillmentSignatureSpi.class);
    putKeyFactory("CryptoConditions", FulfillmentKeyFactorySpi.class);

  }

  private void putSignature(String name, Class<? extends SignatureSpi> engineClass) {
    put("Signature." + name, engineClass.getName());
  };

  private void putKeyFactory(String name, Class<? extends KeyFactorySpi> engineClass) {
    put("KeyFactory." + name, engineClass.getName());
  };



}
