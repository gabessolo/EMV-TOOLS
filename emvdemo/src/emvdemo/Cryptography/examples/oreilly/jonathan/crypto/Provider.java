package oreilly.jonathan.crypto;

import java.security.*;

public class Provider
    extends java.security.Provider {
  public Provider() {
    super ("Jonathan",
        1.2,
        "Jonathan's Cryptography Provider");
    
    put("KeyPairGenerator.ElGamal",
        "oreilly.jonathan.crypto.ElGamalKeyPairGenerator");
    put("Cipher.ElGamal", "oreilly.jonathan.crypto.ElGamalCipher");
    put("Signature.ElGamal", "oreilly.jonathan.crypto.ElGamalSignature");
    
    put("Cipher.DES/CBC/PKCS5Padding",
        "oreilly.jonathan.crypto.CBCWrapper");
    put("Cipher.DES/CFB/NoPadding", "oreilly.jonathan.crypto.CFBWrapper");

    put("Alg.Alias.Cipher.DES/CFB8/NoPadding", "DES/CFB/NoPadding");
  }
}