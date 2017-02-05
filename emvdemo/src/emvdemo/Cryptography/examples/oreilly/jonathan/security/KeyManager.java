package oreilly.jonathan.security;

import java.io.*;
import java.security.*;
import java.text.NumberFormat;
import java.util.*;

public class KeyManager
    extends IdentityScope {
  protected PrivateKey mPrivateKey;
  protected Hashtable mIdentities;

  protected transient String mKeyFile;

  protected KeyManager(String name, KeyPair pair) {
    super(name);
    try { setPublicKey(pair.getPublic()); }
    catch (KeyManagementException kme) {}
    mPrivateKey = pair.getPrivate();
    mIdentities = new Hashtable();
  }

  public int size() { return mIdentities.size(); }
  public Enumeration identities() { return mIdentities.elements(); }
  
  public synchronized Identity getIdentity(String name) {
    Enumeration e = mIdentities.elements();
    while (e.hasMoreElements()) {
      Identity i = (Identity)e.nextElement();
      if (i.getName().equals(name))
        return i;
    }
    return null;
  }
  
  public Identity getIdentity(PublicKey key) {
    return (Identity)mIdentities.get(key);
  }
  
  public synchronized void addIdentity(Identity identity)
      throws KeyManagementException {
    if (mIdentities.contains(identity))
      throw new KeyManagementException("This KeyManager already contains "
          + identity.getName() + ".");
    if (mIdentities.containsKey(identity.getPublicKey()))
      throw new KeyManagementException("This KeyManager already contains "
          + identity.getName() + "'s key.");
    mIdentities.put(identity.getPublicKey(), identity);
  }
    
  public synchronized void removeIdentity(Identity identity)
      throws KeyManagementException {
    PublicKey key = identity.getPublicKey();
    if (mIdentities.containsKey(key))
      mIdentities.remove(key);
    else
      throw new KeyManagementException("This KeyManager does not contain "
          + identity.getName() + ".");
  }

  public synchronized PublicKey getPublicKey(String name) {
    if (name.equals(getName()))
      return getPublicKey();
    return getIdentity(name).getPublicKey();
  }

  public PrivateKey getPrivateKey() { return mPrivateKey; }

  public void addIdentity(String name, PublicKey key)
      throws KeyManagementException {
    Identity i = new KeyManagerIdentity(name);
    i.setPublicKey(key);
    addIdentity(i);
  }

  public static KeyManager getInstance(String file)
      throws IOException, ClassNotFoundException {
    ObjectInputStream in = new ObjectInputStream(
        new FileInputStream(file));
    KeyManager km = (KeyManager)in.readObject();
    in.close();
    km.mKeyFile = file;
    return km;
  }

  public static KeyManager create(String file, String name, KeyPair pair) {
    KeyManager km = new KeyManager(name, pair);
    km.mKeyFile = file;
    return km;
  }

  public synchronized void save() {
    try {
      ObjectOutputStream out = new ObjectOutputStream(
          new FileOutputStream(mKeyFile));
      out.writeObject(this);
      out.close();
    }
    catch (Exception e) {
      System.out.println("KeyManager.save: " + e.toString());
    }
  }

  private static class KeyManagerIdentity
      extends Identity {
    public KeyManagerIdentity(String name) { super(name); }
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      usage();
      return;
    }
    String option = args[0];
    String keyfile = args[1];

    if (option.indexOf("c") != -1) {
      if (args.length < 5) { usage(); return; }
      String signer = args[2];
      String algorithm = args[3];
      int strength = NumberFormat.getInstance().parse(args[4]).intValue();
      System.out.println("Initializing the KeyPairGenerator...");
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
      kpg.initialize(strength);
      System.out.println("Generating the key pair...");
      KeyPair pair = kpg.genKeyPair();
      KeyManager km = create(keyfile, signer, pair);
      km.save();
      System.out.println("Done.");
    }
    else if (option.indexOf("e") != -1) {
      if (args.length < 4) { usage(); return; }
      String idname = args[2];
      String outfile = args[3];
      KeyManager km = getInstance(keyfile);
      ObjectOutputStream out = new ObjectOutputStream(
          new FileOutputStream(outfile));
      PublicKey key = km.getPublicKey(idname);
      out.writeObject(idname);
      out.writeObject(key);
      out.close();
      System.out.println("Done.");
    }
    else if (option.indexOf("i") != -1) {
      if (args.length < 3) { usage(); return; }
      String infile = args[2];
      KeyManager km = getInstance(keyfile);
      ObjectInputStream in = new ObjectInputStream(
          new FileInputStream(infile));
      String idname = (String)in.readObject();
      PublicKey key = (PublicKey)in.readObject();
      in.close();
      km.addIdentity(idname, key);
      km.save();
      System.out.println("Done.");
    }
    else if (option.indexOf("r") != -1) {
      if (args.length < 3) { usage(); return; }
      String idname = args[2];
      KeyManager km = getInstance(keyfile);
      Identity i = km.getIdentity(idname);
      km.removeIdentity(i);
      km.save();
      System.out.println("Done.");
    }
    else if (option.indexOf("l") != -1) {
      if (args.length < 2) { usage(); return; }
      KeyManager km = getInstance(keyfile);
      System.out.println("KeyManager contents of " + keyfile + ":");
      System.out.println("  public and private key for " + km.getName());
      Enumeration e = km.identities();
      while (e.hasMoreElements()) {
        Identity i = (Identity)e.nextElement();
        System.out.println("  public key for " + i.getName());
      }
    }
  }

  protected static void usage() {
    System.out.println("Options:");
    System.out.println("  create: -c keyfile signer algorithm strength");
    System.out.println("  export: -e keyfile idname outfile");
    System.out.println("  import: -i keyfile infile");
    System.out.println("  remove: -r keyfile idname");
    System.out.println("  list  : -l keyfile");
  }
}
