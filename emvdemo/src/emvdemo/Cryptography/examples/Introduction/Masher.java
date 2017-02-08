import java.io.*;
import java.security.*;

import sun.misc.*;

public class Masher {
  public static void main(String[] args) throws Exception {
    // Check arguments.
    if (args.length != 1) {
      System.out.println("Usage: Masher filename");
      return;
    }

    // Obtain a message digest object.
    MessageDigest md = MessageDigest.getInstance("MD5");

    // Calculate the digest for the given file.
    FileInputStream in = new FileInputStream(args[0]);
    byte[] buffer = new byte[8192];
    int length;
    while ((length = in.read(buffer)) != -1)
      md.update(buffer, 0, length);
    byte[] raw = md.digest();

    // Print out the digest in base64.
    BASE64Encoder encoder = new BASE64Encoder();
    String base64 = encoder.encode(raw);
    System.out.println(base64);
  }
}