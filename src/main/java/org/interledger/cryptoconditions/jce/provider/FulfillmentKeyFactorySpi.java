package org.interledger.cryptoconditions.jce.provider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.IllegalFulfillmentException;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.jce.provider.keys.DefaultConditionPublicKey;
import org.interledger.cryptoconditions.jce.spec.ConditionKeySpec;
import org.interledger.cryptoconditions.jce.spec.OerEncodedConditionKeySpec;
import org.interledger.cryptoconditions.jce.spec.OerEncodedFulfillmentKeySpec;
import org.interledger.cryptoconditions.oer.OerDecodingException;
import org.interledger.cryptoconditions.oer.OerUtil;

public class FulfillmentKeyFactorySpi extends KeyFactorySpi {

  /**
   * Get a crypto-condition from an encoded key spec
   */
  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof OerEncodedFulfillmentKeySpec) {
      try {
        final Fulfillment fulfillment =
            OerUtil.getFullfillment(((OerEncodedFulfillmentKeySpec) keySpec).getEncoded());
        final Condition condition = fulfillment.getCondition();

        return new DefaultConditionPublicKey(new ConditionKeySpec(condition));

      } catch (IOException e) {
        throw new InvalidKeySpecException("Error decoding fulfillment.", e);
      } catch (UnsupportedConditionException e) {
        throw new InvalidKeySpecException("Unsupported fulfillment.", e);
      } catch (OerDecodingException e) {
        throw new InvalidKeySpecException("Error decoding fulfillment.", e);
      } catch (IllegalFulfillmentException e) {
        throw new InvalidKeySpecException("Unsupported fulfillment.", e);
      }

    }

    if (keySpec instanceof OerEncodedConditionKeySpec) {
      try {
        return new DefaultConditionPublicKey((OerEncodedConditionKeySpec) keySpec);
      } catch (UnsupportedConditionException e) {
        throw new InvalidKeySpecException("Unsupported fulfillment.", e);
      } catch (OerDecodingException e) {
        throw new InvalidKeySpecException("Error decoding fulfillment.", e);
      }
    }

    if (keySpec instanceof ConditionKeySpec) {
      return new DefaultConditionPublicKey((ConditionKeySpec) keySpec);
    }

    throw new InvalidKeySpecException("Unknown keyspec type.");


  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    throw new UnsupportedOperationException("This KeyFactory does not support private keys.");
  }

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  protected Key engineTranslateKey(Key key) throws InvalidKeyException {
    // TODO Auto-generated method stub
    return null;
  }

}
