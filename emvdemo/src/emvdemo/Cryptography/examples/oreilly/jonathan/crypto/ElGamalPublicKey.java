package oreilly.jonathan.crypto;

import java.math.BigInteger;
import java.security.*;

public class ElGamalPublicKey
    extends ElGamalKey
    implements PublicKey {
  private BigInteger mY;
  
  protected ElGamalPublicKey(BigInteger y, BigInteger g, BigInteger p) {
    super(g, p);
    mY = y;
  }
  
  protected BigInteger getY() { return mY; }
}