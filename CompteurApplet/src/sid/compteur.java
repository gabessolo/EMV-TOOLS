/**
 * 
 */
package sid;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * @author root
 *
 */
public class compteur extends Applet {
    private byte compteur=0;
    private final static byte CLS=(byte)0xB0;
    private final static byte INC=0x00;
    private final static byte DEC=0x01;
    private final static byte GET=0x02;
    private final static byte INIT=0x03;
    
	private compteur() {
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new compteur().register();
	}

	/* (non-Javadoc)
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	
	public void process(APDU apdu) throws ISOException {
		// TODO Auto-generated method stub
		if (this.selectingApplet()) return;
		
		
		byte[] buffer=apdu.getBuffer();
		byte cls=buffer[ISO7816.OFFSET_CLA];
		byte ins=buffer[ISO7816.OFFSET_INS];
		
		if (cls!=CLS) 
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		switch(ins)
		{
		case INC:compteur++;break;
		case DEC:compteur--;break;
		
		case INIT:apdu.setIncomingAndReceive();
				  compteur=buffer[ISO7816.OFFSET_CDATA];	
				  break;
		case GET:   buffer[0]=compteur;
					apdu.setOutgoingAndSend((short)0,(short) 1);
					break;
		default:	ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
					break;
		}
	}
}
