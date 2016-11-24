package org.interledger.cryptoconditions.util;

public class Base16 {

  private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

  public static String encode(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static byte[] decode(String s) {
    if (s == null || (s.length() % 2) == 1)
      throw new IllegalArgumentException("Input must be valid base16 encoded data.");

    char[] chars = s.toCharArray();
    int len = chars.length;
    byte[] bytes = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      bytes[i / 2] =
          (byte) ((Character.digit(chars[i], 16) << 4) + Character.digit(chars[i + 1], 16));
    }
    return bytes;
  }
}
