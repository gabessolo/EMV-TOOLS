import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Date;

import Protection;

public class StrongClient {
  public void sendAuthentication(String user, PrivateKey key,
      OutputStream outStream) throws IOException, NoSuchAlgorithmException,
      InvalidKeyException, SignatureException {
    DataOutputStream out = new DataOutputStream(outStream);
    long t = (new Date()).getTime();
    double q = Math.random();

    Signature s = Signature.getInstance("DSA");
    s.initSign(key);
    s.update(Protection.makeBytes(t, q));
    byte[] signature = s.sign();

    out.writeUTF(user);
    out.writeLong(t);
    out.writeDouble(q);
    out.writeInt(signature.length);
    out.write(signature);
    out.flush();
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      System.out.println(
          "Usage: StrongClient host keystore storepass alias keypass");
      return;
    }
    
    String host = args[0];
    String keystorefile = args[1];
    String storepass = args[2];
    String alias = args[3];
    String keypass = args[4];
    
    int port = 7999;
    Socket s = new Socket(host, port);

    StrongClient client = new StrongClient();
    KeyStore keystore = KeyStore.getInstance();
    keystore.load(new FileInputStream(keystorefile), storepass);
    PrivateKey key = keystore.getPrivateKey(alias, keypass);
    client.sendAuthentication(alias, key, s.getOutputStream());

    s.close();
  }
}