

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class MainClass {

  public static void main(String[] args) throws Exception {
    String keystoreFilename = "my.keystore";

    char[] password = "password".toCharArray();
    String alias = "alias";

    FileInputStream fIn = new FileInputStream(keystoreFilename);
    KeyStore keystore = KeyStore.getInstance("JKS");

    keystore.load(fIn, password);

    Certificate cert = keystore.getCertificate(alias);

    System.out.println(cert);
  }
}


import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class MainClass {

  public static void main(String[] args) throws Exception {

    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

    FileInputStream fis = new FileInputStream("a.dat");

    Certificate cert = certFactory.generateCertificate(fis);
    fis.close();

    System.out.println(cert);
  }
}

import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

public class MainClass {
  public static void main(String args[]) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List mylist = new ArrayList();
    for (int i = 0; i < args.length; i++) {
      FileInputStream in = new FileInputStream(args[i]);
      Certificate c = cf.generateCertificate(in);
      mylist.add(c);
    }
    CertPath cp = cf.generateCertPath(mylist);
    System.out.println(cp);
  }
}


//exporter un certificat

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class Main {
  public static void main(String[] argv) throws Exception {
    FileInputStream is = new FileInputStream("your.keystore");

    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
    keystore.load(is, "my-keystore-password".toCharArray());

    String alias = "myalias";
    Certificate cert = keystore.getCertificate(alias);

    File file = null;
    byte[] buf = cert.getEncoded();

    FileOutputStream os = new FileOutputStream(file);
    os.write(buf);
    os.close();

    Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
    wr.write(new sun.misc.BASE64Encoder().encode(buf));
    wr.flush();

  }
}

//importer un certificat

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;

public class MainClass {
  public static void main(String args[]) throws Exception {
    String cacert = "mytest.cer";
    String lfcert = "lf_signed.cer";
    String lfstore = "lfkeystore";
    char[] lfstorepass = "wshr.ut".toCharArray();
    char[] lfkeypass = "wshr.ut".toCharArray();
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    FileInputStream in1 = new FileInputStream(cacert);
    java.security.cert.Certificate cac = cf.generateCertificate(in1);
    in1.close();
    FileInputStream in2 = new FileInputStream(lfcert);
    java.security.cert.Certificate lfc = cf.generateCertificate(in2);
    in2.close();
    java.security.cert.Certificate[] cchain = { lfc, cac };
    FileInputStream in3 = new FileInputStream(lfstore);
    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(in3, lfstorepass);
    PrivateKey prk = (PrivateKey) ks.getKey("lf", lfkeypass);
    ks.setKeyEntry("lf_signed", prk, lfstorepass, cchain);
    FileOutputStream out4 = new FileOutputStream("lfnewstore");
    ks.store(out4, "newpass".toCharArray());
    out4.close();
  }
}

//valider un certificat

import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainClass {

  public static void main(String args[]) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List mylist = new ArrayList();
    FileInputStream in = new FileInputStream(args[0]);
    Certificate c = cf.generateCertificate(in);
    mylist.add(c);

    CertPath cp = cf.generateCertPath(mylist);

    Certificate trust = cf.generateCertificate(in);
    TrustAnchor anchor = new TrustAnchor((X509Certificate) trust, null);
    PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
    params.setRevocationEnabled(false);
    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
    PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
    System.out.println(result);
  }
}

