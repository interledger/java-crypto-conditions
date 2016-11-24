package org.interledger.cryptoconditions.uri;

import java.io.UnsupportedEncodingException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.FeatureSuite;

public class UriEncoding {

  public static String toUri(Condition condition) throws UnsupportedEncodingException {

    StringBuffer sb = new StringBuffer();

    sb.append(ConditionWriter.getHeader());
    sb.append(ConditionWriter.getDelimiter());
    sb.append(condition.getType().getTypeCode());
    sb.append(ConditionWriter.getDelimiter());

    EnumSet<FeatureSuite> fsSet = condition.getFeatures();
    int features = 0;

    if (fsSet != null) {
      for (FeatureSuite fs : fsSet) {
        features |= fs.getBitIndex();
      }
    }

    sb.append(features);
    sb.append(ConditionWriter.getDelimiter());
    sb.append(new String(condition.getFingerprint(), "UTF-8"));
    sb.append(ConditionWriter.getDelimiter());
    sb.append(condition.getMaxFulfillmentLength());

    return sb.toString();
  }
}
