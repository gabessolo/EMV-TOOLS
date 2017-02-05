package emvdemoBook;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;

public class EmvdemoBookApplet extends Applet {

	private EmvdemoBookApplet() {
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new EmvdemoBookApplet().register();
	}

	
	public void process(APDU arg0) throws ISOException {
		// TODO Auto-generated method stub

	}

}
