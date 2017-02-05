
private static byte[] getRawKey(byte[] seed) throws Exception {
  KeyGenerator kgen=KeyGenerator.getInstance("AES");
  SecureRandom sr=SecureRandom.getInstance("SHA1PRNG");
  sr.setSeed(seed);
  kgen.init(128,sr);
  SecretKey skey=kgen.generateKey();
  byte[] raw=skey.getEncoded();
  return raw;
}

public byte[] generateRawKey(String algorithm){
  KeyGenerator keyGen;
  try {
    keyGen=KeyGenerator.getInstance(algorithm);
    SecretKey key=keyGen.generateKey();
    byte[] keyBytes=key.getEncoded();
    return keyBytes;
  }
 catch (  NoSuchAlgorithmException e) {
    e.printStackTrace();
  }
  return null;
}

/** 
 * Make a KeyBundle with two random 256 bit keys (encryption and HMAC).
 * @return A KeyBundle with random keys.
 */
public static KeyBundle withRandomKeys() throws CryptoException {
  KeyGenerator keygen;
  try {
    keygen=KeyGenerator.getInstance(KEY_ALGORITHM_SPEC);
  }
 catch (  NoSuchAlgorithmException e) {
    throw new CryptoException(e);
  }
  keygen.init(KEY_SIZE);
  byte[] encryptionKey=keygen.generateKey().getEncoded();
  byte[] hmacKey=keygen.generateKey().getEncoded();
  return new KeyBundle(encryptionKey,hmacKey);
}

public static Cipher getCipher(int mode,byte[] secret) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
  SecureRandom secureRandom=SecureRandom.getInstance(RANDOM_ALGORITHM);
  secureRandom.setSeed(secret);
  KeyGenerator keyGenerator=KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
  keyGenerator.init(KEY_SIZE,secureRandom);
  Key key=new SecretKeySpec(keyGenerator.generateKey().getEncoded(),ENCRYPTION_ALGORITHM);
  Cipher cipher=Cipher.getInstance(ENCRYPTION_ALGORITHM);
  cipher.init(mode,key);
  return cipher;
}

private byte[] getKey(String passphrase){
  try {
    KeyGenerator kgen=KeyGenerator.getInstance(CIPHER_ALGORITHM);
    SecureRandom sr=SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed(passphrase.getBytes());
    kgen.init(128,sr);
    SecretKey skey=kgen.generateKey();
    return skey.getEncoded();
  }
 catch (  NoSuchAlgorithmException e) {
    throw new RuntimeException(e);
  }
}

private static SecretKey generateSecretKey(){
  try {
    KeyGenerator kg=KeyGenerator.getInstance("DES");
    return kg.generateKey();
  }
 catch (  NoSuchAlgorithmException e) {
    throw new RuntimeException(e);
  }
}





