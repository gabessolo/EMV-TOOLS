import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class Shorts {
  public static void main(String[] args) throws Exception {
  }
  
  public void kpg() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
    kpg.initialize(1024);
    KeyPair pair = kpg.genKeyPair();
  }
  
  public void kg() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("DES");
    kg.init(new SecureRandom());
    SecretKey key = kg.generateKey();
  }
  
  public SecretKey makeDESKey(byte[] input, int offset)
      throws NoSuchAlgorithmException, InvalidKeyException,
      InvalidKeySpecException {
    SecretKeyFactory desFactory = SecretKeyFactory.getInstance("DES");
    KeySpec spec = new DESKeySpec(input, offset);
    return desFactory.generateSecret(spec);
  }

  public byte[] makeBytesFromDESKey(SecretKey key)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory desFactory = SecretKeyFactory.getInstance("DES");
    DESKeySpec spec =
        (DESKeySpec)desFactory.getKeySpec(key, DESKeySpec.class);
    return spec.getKey();
  }

	public void printKey(Identity i) {
	  PublicKey k = i.getPublicKey();
	  System.out.println("  Public key uses " + k.getAlgorithm() +
	      " and is encoded with " + k.getFormat() + ".");
	}
}