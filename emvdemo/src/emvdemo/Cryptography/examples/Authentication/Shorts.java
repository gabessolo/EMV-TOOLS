import java.io.*;
import java.security.*;

public class Shorts {
  public void md(byte[] inputData) throws Exception {
		// Define byte[] inputData first.
		MessageDigest md = MessageDigest.getInstance("SHA");
		md.update(inputData);
		byte[] digest = md.digest();
  }
  
  public void fromMasher(String[] args) throws Exception{
    // Obtain a message digest object.
    MessageDigest md = MessageDigest.getInstance("MD5");

    // Calculate the digest for the given file.
    FileInputStream in = new FileInputStream(args[0]);
    byte[] buffer = new byte[8192];
    int length;
    while ((length = in.read(buffer)) != -1)
        md.update(buffer, 0, length);
    byte[] raw = md.digest();
  }
  
  public void withStream(String[] args) throws Exception {
    // Obtain a message digest object.
    MessageDigest md = MessageDigest.getInstance("MD5");

    // Calculate the digest for the given file.
    DigestInputStream in = new DigestInputStream(
        new FileInputStream(args[0]), md);
    byte[] buffer = new byte[8192];
    while (in.read(buffer) != -1)
      ;
    byte[] raw = md.digest();
  }
}