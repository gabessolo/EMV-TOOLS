package oreilly.jonathan.crypto;

import java.math.BigInteger;
import java.security.*;

public class ElGamalKey
    implements Key {
  private BigInteger mP, mG;
  
  protected ElGamalKey(BigInteger g, BigInteger p) {
    mG = g;
    mP = p;
  }
  
  protected BigInteger getG() { return mG; }
  protected BigInteger getP() { return mP; }
  
  public String getAlgorithm() { return "ElGamal"; }
  public String getFormat() { return "NONE"; }
  public byte[] getEncoded() { return null; }
}