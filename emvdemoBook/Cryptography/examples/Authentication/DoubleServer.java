import java.io.*;
import java.net.*;
import java.security.*;

import Protection;

public class DoubleServer {
  public boolean authenticate(InputStream inStream)
      throws IOException, NoSuchAlgorithmException {
    DataInputStream in = new DataInputStream(inStream);

    String user = in.readUTF();
    long t1 = in.readLong();
    double q1 = in.readDouble();
    long t2 = in.readLong();
    double q2 = in.readDouble();
    int length = in.readInt();
    byte[] protected2 = new byte[length];
    in.readFully(protected2);

    String password = lookupPassword(user);
    byte[] local1 = Protection.makeDigest(user, password, t1, q1);
    byte[] local2 = Protection.makeDigest(local1, t2, q2);
    return MessageDigest.isEqual(protected2, local2);
  }

  protected String lookupPassword(String user) { return "buendia"; }

  public static void main(String[] args) throws Exception {
    int port = 7999;
    ServerSocket s = new ServerSocket(port);
    Socket client = s.accept();

    DoubleServer server = new DoubleServer();
    if (server.authenticate(client.getInputStream()))
      System.out.println("Client logged in.");
    else
      System.out.println("Client failed to log in.");

    s.close();
  }
}