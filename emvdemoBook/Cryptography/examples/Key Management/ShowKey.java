import java.security.*;
import java.util.*;

public class ShowKey {
  public static void main(String[] args) {
    if (args.length < 1) {
      System.out.println("Usage: ShowKey name");
      return;
    }

    IdentityScope systemScope = IdentityScope.getSystemScope();
    Identity i = systemScope.getIdentity(args[0]);
    Key k = i.getPublicKey();
    if (k != null) {
      System.out.println("  Public key uses " + k.getAlgorithm() +
          " and is encoded by " + k.getFormat() + ".");
    }
  }
}