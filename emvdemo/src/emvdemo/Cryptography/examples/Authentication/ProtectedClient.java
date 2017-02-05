import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Date;

import Protection;

public class ProtectedClient {
  public void sendAuthentication(String user, String password,
      OutputStream outStream) throws IOException, NoSuchAlgorithmException {
    DataOutputStream out = new DataOutputStream(outStream);
    long t1 = (new Date()).getTime();
    double q1 = Math.random();
    byte[] protected1 = Protection.makeDigest(user, password, t1, q1);

    out.writeUTF(user);
    out.writeLong(t1);
    out.writeDouble(q1);
    out.writeInt(protected1.length);
    out.write(protected1);
    out.flush();
  }

  public static void main(String[] args) throws Exception {
    String host = args[0];
    int port = 7999;
    String user = "Jonathan";
    String password = "buendia";
    Socket s = new Socket(host, port);

    ProtectedClient client = new ProtectedClient();
    client.sendAuthentication(user, password, s.getOutputStream());

    s.close();
  }
}