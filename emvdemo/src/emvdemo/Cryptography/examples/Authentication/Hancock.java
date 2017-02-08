import java.io.*;
import java.security.*;

public class Hancock {
  public static void main(String[] args) throws Exception {
    if (args.length != 6) {
      System.out.println(
          "Usage: Hancock -s|-v keystore storepass alias " +
          "messagefile signaturefile");
      return;
    }
    
    String options = args[0];
    String keystorefile = args[1];
    String storepass = args[2];
    String alias = args[3];
    String messagefile = args[4];
    String signaturefile = args[5];

    Signature signature = Signature.getInstance("DSA");

    KeyStore keystore = KeyStore.getInstance();
    keystore.load(new FileInputStream(keystorefile), storepass);

    if (options.indexOf("s") != -1)
      signature.initSign(keystore.getPrivateKey(alias, storepass));
    else
      signature.initVerify(keystore.getCertificate(alias).getPublicKey());

    FileInputStream in = new FileInputStream(messagefile);
    byte[] buffer = new byte[8192];
    int length;
    while ((length = in.read(buffer)) != -1)
      signature.update(buffer, 0, length);
    in.close();

    if (options.indexOf("s") != -1) {
      FileOutputStream out = new FileOutputStream(signaturefile);
      byte[] raw = signature.sign();
      out.write(raw);
      out.close();
    }

    else {
      FileInputStream sigIn = new FileInputStream(signaturefile);
      byte[] raw = new byte[sigIn.available()];
      sigIn.read(raw);
      sigIn.close();
      if (signature.verify(raw))
        System.out.println("The signature is good.");
      else
        System.out.println("The signature is bad.");
    }
  }
}