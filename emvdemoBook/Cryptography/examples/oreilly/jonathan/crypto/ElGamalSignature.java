package oreilly.jonathan.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;

public class ElGamalSignature
    extends SignatureSpi {

  protected ElGamalKey mKey;

  protected ByteArrayOutputStream mOut;

  protected static BigInteger kOne = BigInteger.valueOf(1);
  
  protected void engineInitVerify(PublicKey key)
      throws InvalidKeyException {
    if (!(key instanceof ElGamalPublicKey))
      throw new InvalidKeyException("I didn't get an ElGamalPublicKey.");
    mKey = (ElGamalKey)key;
    mOut = new ByteArrayOutputStream();
  }

  protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
    if (!(key instanceof ElGamalPrivateKey))
      throw new InvalidKeyException("I didn't get an ElGamalPrivateKey.");
    mKey = (ElGamalKey)key;
    mOut = new ByteArrayOutputStream();
  }

  protected void engineUpdate(byte b) throws SignatureException {
    mOut.write(b);
  }
  
  protected void engineUpdate(byte[] b, int off, int len)
      throws SignatureException {
    mOut.write(b, off, len);
  }

  protected byte[] engineSign() throws SignatureException {
    BigInteger x = ((ElGamalPrivateKey)mKey).getX();
    BigInteger g = mKey.getG();
    BigInteger p = mKey.getP();
    BigInteger pminusone = p.subtract(kOne);

    BigInteger k;
    do {
      k = new BigInteger(p.bitLength() - 1, new SecureRandom());
    } while (k.gcd(pminusone).equals(kOne) == false);

    BigInteger m = new BigInteger(1, mOut.toByteArray());

    BigInteger a = g.modPow(k, p);
    BigInteger top = m.subtract(x.multiply(a)).mod(pminusone);
    BigInteger b = top.multiply(
        k.modPow(kOne.negate(), pminusone)).mod(pminusone);

    int modulusLength = (p.bitLength() + 7) / 8;
    byte[] signature = new byte[modulusLength * 2];
    byte[] aBytes = getBytes(a);
    int aLength = aBytes.length;
    byte[] bBytes = getBytes(b);
    int bLength = bBytes.length;
    System.arraycopy(aBytes, 0,
        signature, modulusLength - aLength, aLength);
    System.arraycopy(bBytes, 0,
        signature, modulusLength * 2 - bLength, bLength);
    return signature;
  }

  protected boolean engineVerify(byte[] sigBytes)
      throws SignatureException {
    BigInteger y = ((ElGamalPublicKey)mKey).getY();
    BigInteger g = mKey.getG();
    BigInteger p = mKey.getP();

    int modulusLength = (p.bitLength() + 7) / 8;
    byte[] aBytes = new byte[modulusLength];
    byte[] bBytes = new byte[modulusLength];
    System.arraycopy(sigBytes, 0, aBytes, 0, modulusLength);
    System.arraycopy(sigBytes, modulusLength, bBytes, 0, modulusLength);
    BigInteger a = new BigInteger(1, aBytes);
    BigInteger b = new BigInteger(1, bBytes);

    BigInteger first = y.modPow(a, p).multiply(a.modPow(b, p)).mod(p);

    BigInteger m = new BigInteger(1, mOut.toByteArray());
    BigInteger second = g.modPow(m,p);
    
    return first.equals(second);
  }

  protected byte[] getBytes(BigInteger big) {
    byte[] bigBytes = big.toByteArray();
    if ((big.bitLength() % 8) != 0) {
      return bigBytes;
    }
    else {
      byte[] smallerBytes = new byte[big.bitLength() / 8];
      System.arraycopy(bigBytes, 1, smallerBytes, 0, smallerBytes.length);
      return smallerBytes;
    }
  }

  protected void engineSetParameter(String param, Object value)
      throws InvalidParameterException {}
  protected Object engineGetParameter(String param)
      throws InvalidParameterException { return null; }
}