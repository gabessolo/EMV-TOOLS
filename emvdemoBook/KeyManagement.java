package emvdemo;


import java.io.*;
import java.security.*;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import javacard.security.SecretKey;
import javacardx.crypto.Cipher;

import java.nio.*;


public class KeyManagement {


private KeyGenerator kgen;
private SecureRandom secureRandom;
	
public KeyManagement() {}

private  byte[] getRawKey(byte[] seed) throws Exception {
  kgen=KeyGenerator.getInstance("AES");
  SecureRandom sr=SecureRandom.getInstance("SHA1PRNG");
  sr.setSeed(seed);
  kgen.init(128,sr);
  SecretKey skey=(SecretKey) kgen.generateKey();
  byte[] raw=((Key) skey).getEncoded();
  return raw;
}

public byte[] generateRawKey(String algorithm){
  
  try {
    kgen=KeyGenerator.getInstance(algorithm);
    SecretKey key=(SecretKey) kgen.generateKey();
    byte[] keyBytes=((Key) key).getEncoded();
    return keyBytes;
  }
 catch (  NoSuchAlgorithmException e) {
   // e.printStackTrace();
  }
  return null;
}

public Cipher getCipher(int mode,byte[] secret) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
  secureRandom=SecureRandom.getInstance(RANDOM_ALGORITHM);
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
    SecretKey skey=(SecretKey) kgen.generateKey();
    return ((Key) skey).getEncoded();
  }
 catch (  NoSuchAlgorithmException e) {
    throw new RuntimeException();
  }
}

private  SecretKey generateSecretKey(){
  try {
    kgen=KeyGenerator.getInstance("DES");
    return (SecretKey) kgen.generateKey();
  }
 catch (  NoSuchAlgorithmException e) {
    throw new RuntimeException();
  }
}


	
	
	
}
