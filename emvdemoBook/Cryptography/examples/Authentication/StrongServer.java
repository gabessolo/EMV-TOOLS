import java.io.*;
import java.net.*;
import java.security.*;

import Protection;

public class StrongServer {
  protected KeyStore mKeyStore;
  
  public StrongServer(KeyStore keystore) { mKeyStore = keystore; }
  
  public boolean authenticate(InputStream inStream)
      throws IOException, NoSuchAlgorithmException,
      InvalidKeyException, SignatureException {
    DataInputStream in = new DataInputStream(inStream);

    String user = in.readUTF();
    long t = in.readLong();
    double q = in.readDouble();
    int length = in.readInt();
    byte[] signature = new byte[length];
    in.readFully(signature);

    Signature s = Signature.getInstance("DSA");
    s.initVerify(mKeyStore.getCertificate(user).getPublicKey());
    s.update(Protection.makeBytes(t, q));
    return s.verify(signature);
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      System.out.println("Usage: StrongServer keystore storepass");
      return;
    }
    
    String keystorefile = args[0];
    String storepass = args[1];
    
    int port = 7999;
    ServerSocket s = new ServerSocket(port);
    Socket client = s.accept();

    KeyStore keystore = KeyStore.getInstance();
    keystore.load(new FileInputStream(keystorefile), storepass);
    StrongServer server = new StrongServer(keystore);
    if (server.authenticate(client.getInputStream()))
      System.out.println("Client logged in.");
    else
      System.out.println("Client failed to log in.");

    s.close();
  }
}