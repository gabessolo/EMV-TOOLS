import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Date;

import Protection;

public class DoubleClient {
  public void sendAuthentication(String user, String password,
      OutputStream outStream) throws IOException, NoSuchAlgorithmException {
    DataOutputStream out = new DataOutputStream(outStream);
    long t1 = (new Date()).getTime();
    double q1 = Math.random();
    byte[] protected1 = Protection.makeDigest(user, password, t1, q1);
    long t2 = (new Date()).getTime();
    double q2 = Math.random();
    byte[] protected2 = Protection.makeDigest(protected1, t2, q2);

    out.writeUTF(user);
    out.writeLong(t1);
    out.writeDouble(q1);
    out.writeLong(t2);
    out.writeDouble(q2);
    out.writeInt(protected2.length);
    out.write(protected2);
    out.flush();
  }

  public static void main(String[] args) throws Exception {
    String host = args[0];
    int port = 7999;
    String user = "Jonathan";
    String password = "buendia";
    Socket s = new Socket(host, port);

    DoubleClient client = new DoubleClient();
    client.sendAuthentication(user, password, s.getOutputStream());

    s.close();
  }
}