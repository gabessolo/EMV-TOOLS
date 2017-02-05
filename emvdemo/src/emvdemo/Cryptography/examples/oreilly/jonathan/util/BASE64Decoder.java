package oreilly.jonathan.util;

public class BASE64Decoder {
  public byte[] decodeBuffer(String base64) {
    return Base64.decode(base64);
  }
}