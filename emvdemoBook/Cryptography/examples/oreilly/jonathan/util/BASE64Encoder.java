package oreilly.jonathan.util;

public class BASE64Encoder {
  public String encode(byte[] raw) {
    return Base64.encode(raw);
  }
}