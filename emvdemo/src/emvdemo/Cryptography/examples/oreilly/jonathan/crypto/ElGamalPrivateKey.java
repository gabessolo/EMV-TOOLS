package oreilly.jonathan.crypto;

import java.math.BigInteger;
import java.security.*;

public class ElGamalPrivateKey
    extends ElGamalKey
    implements PrivateKey {
  private BigInteger mX;
  
  protected ElGamalPrivateKey(BigInteger x, BigInteger g, BigInteger p) {
    super(g, p);
    mX = x;
  }
  
  protected BigInteger getX() { return mX; }
}