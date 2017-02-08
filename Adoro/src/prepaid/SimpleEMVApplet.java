/* 
 * Copyright (C) 2011  Digital Security group, Radboud University
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package prepaid;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacard.framework.ISO7816;

/* A very basic EMV applet supporting only SDA and plaintext offline PIN.
 * This applet does not offer personalisation support - everything is hard-coded.
 * 
 * The code is optimised for readability, and not for performance or memory use.
 * 
 * This class does the central processing of APDUs. Handling of all crypto-related
 * stuff is outsourced to EMVCrypro, handling of the static card data to EMVStaticData,
 * and handling of the EMV protocol and session state to EMVProtocolState.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 * 
 */
public class SimpleEMVApplet extends Applet implements EMVConstants {

	 static OwnerPIN pin;
	 static RandomData randomData;
	 static EMVCrypto theCrypto;
	 static EMVProtocolState protocolState;
	 static EMVStaticData staticData;
	 // signal that the PIN verification failed
	 final static short SW_VERIFICATION_FAILED = 0x6300;

	/* Transient byte array for constructing APDU responses. 
	 * We could have used the APDU buffer for this, but then we have to be careful not to 
	 * overwrite any info in the instruction APDU that we still need.
	 */
	private  static byte[] response;
	
    private static byte[] AID_Selected=null;
    
	private SimpleEMVApplet() {
		response = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);

		//pin = new OwnerPIN((byte) 3, (byte) 2);
		pin=new OwnerPIN(EMVConstants.PIN_TRY_LIMIT,EMVConstants.PIN_MAX_LEN);

		pin.update(new byte[] { (byte) 0x12, (byte) 0x34 }, (short) 0, (byte) 2);
		
		randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		
		protocolState = new EMVProtocolState(this);
		staticData = new EMVStaticData();
		theCrypto = new EMVCrypto(this);
		
		protocolState.initPinTry();
		
		
	} 
	
	public boolean Select (APDU apdu)
	{
		byte[] apduBuffer = apdu.getBuffer();
		short numBytes=apduBuffer[ISO7816.OFFSET_LC];
				
		if (AID_Selected==null)
			 AID_Selected=new byte[/*numBytes*/0xE0];
		
		Util.arrayCopyNonAtomic(apduBuffer,ISO7816.OFFSET_CDATA,AID_Selected, (short)0, (short)numBytes);
		
		protocolState.startNewSession();
		protocolState.setAppSelected();
		apdu.setOutgoing();
		apdu.setOutgoingLength(staticData.getFCILength(AID_Selected));
		apdu.sendBytesLong(staticData.getFCI(AID_Selected), (short)0, staticData.getFCILength(AID_Selected));
		
		return true;
	}  
	/**
	 * Installs an instance of the applet.
	 * 
	 * @see javacard.framework.Applet#install(byte[], byte, byte)
	 */
	public static void install(byte[] buffer, short offset, byte length) {
		(new SimpleEMVApplet()).register();
	}

	/**
	 * Processes incoming APDUs.
	 * 
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		byte cla = apduBuffer[ISO7816.OFFSET_CLA];
		byte ins = apduBuffer[ISO7816.OFFSET_INS];

		if (cla!=CLS_ISO && cla!=CLS_MANUFACTURE )
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		/*
		if (selectingApplet()) {
			// Reset all the flags recording the protocol state.
			// This should already have happened by the clearing of the
			// transient array used for them.
			
			Util.arrayCopyNonAtomic(apduBuffer,ISO7816.OFFSET_CDATA,AID_Selected, (short)0, (short)apduBuffer[ISO7816.OFFSET_LC]);
			
			protocolState.startNewSession();
			protocolState.setAppSelected();
			apdu.setOutgoing();
			apdu.setOutgoingLength(staticData.getFCILength(AID_Selected));
			apdu.sendBytesLong(staticData.getFCI(AID_Selected), (short)0, staticData.getFCILength(AID_Selected));
			
			return;
		}*/

		
	    switch (ins) {

	    case INS_SELECT:
	    		Select(apdu);
	    		break;
	    
	    case INS_EXTERNAL_AUTHENTICATE: // 0x82
    		//issuerAuthenticate();
			break;

		case INS_GET_CHALLENGE: // 0x84
			getChallenge(apdu, apduBuffer);
			break;

		case INS_INTERNAL_AUTHENTICATE:
			//sdaAuthenticate();
			break;

		case INS_READ_RECORD: // 0xB2
			
			/*if (protocolState.getAppSelected()==0)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			if (protocolState.getProcPerformed()==0)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			*/
			readRecord(apdu, response,AID_Selected);
			break;

		case INS_GET_PROCESSING_OPTIONS: // 0xA8
			
			//if (protocolState.getAppSelected()==0)
			//	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			getProcessingOptions(apdu, response,AID_Selected);
			break;

		case INS_GET_DATA: // 0xCA
			
			//if (protocolState.getAppSelected()==0)
			//	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			//if (protocolState.getProcPerformed()==0)
			//	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			getData(apdu, apduBuffer);
			break;

		case INS_VERIFY: // 0x20
			
			//if (protocolState.getAppSelected()==0)
			//	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			verify(apdu);
			
			break;

		case INS_GENERATE_AC: // 0xAE
			
			//if (protocolState.getPINValidate()==false)
			//	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			//if (protocolState.getPinTry()>=PIN_TRY_LIMIT)
			//	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			//if (protocolState.getProcPerformed()==0)
			//	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
					
			// get remaining data
			short len = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
			if (len != apdu.setIncomingAndReceive()) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			// check for request of CDA signature
			//if ((apduBuffer[ISO7816.OFFSET_P1] & 0x10) == 0x10) {
			//	// CDA signature requested, which we don't support (yet)
			//	ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			//}
			
			if (protocolState.getFirstACGenerated() == NONE) {
				generateFirstAC(apdu, apduBuffer,AID_Selected);
			} else if (protocolState.getSecondACGenerated() == NONE) {
				generateSecondAC(apdu, apduBuffer,AID_Selected);
			} else
				// trying to generate a third AC
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;

		// below the (unsupported) post-issuance commands
		case INS_APPLICATION_BLOCK:
		case INS_APPLICATION_UNBLOCK:
		case INS_CARD_BLOCK:
		case INS_PIN_CHANGE_UNBLOCK:
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
	    //à executer après une transaction accepté pour récuperer
	    //la clé de session
	    //case INS_GET_SK: getSK();
	    //		break;
	}
 
	/*
	 * The VERIFY command checks the pin. This implementation only supports
	 * transaction_data PIN.
	 */	
		
	private void verify(APDU apdu) {
	    byte[] buffer = apdu.getBuffer();
	    // retrieve the PIN data for validation.
	    byte byteRead = (byte)(apdu.setIncomingAndReceive());
	   
	    if (buffer[ISO7816.OFFSET_P2] != (byte) (0x80)) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2); // we only support transaction_data PIN
		}
	    
	    if (pin.getTriesRemaining() == 0) 
		{
			ISOException.throwIt((short) 0x6983); // PIN blocked
			return;
		}
	    // check pin
	    // the PIN data is read into the APDU buffer
	    // at the offset ISO7816.OFFSET_CDATA
	    // the PIN data length = byteRead
	    
	    
	    short numBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		/*
		 * Here I suppose the PIN code is small enough to fit into the buffer
		 * TODO: Verify the assumption and eventually adjust code to support
		 * reading PIN in multiple read()s
		 */
		if (numBytes != byteRead )
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) numBytes)) {
			ISOException.throwIt((short)(SW_VERIFICATION_FAILED) );
		}
	    
		//protocolState.setCVMPerformed(PLAINTEXT_PIN);
		//protocolState.setPINValidate();
		
	    apdu.setOutgoingAndSend((short) 0, (short) 0); // return 9000  
	}

	/*
	 * The GET CHALLENGE command generates an 8 byte unpredictable number.
	 */
	private void getChallenge(APDU apdu, byte[] buffer) {
		randomData.generateData(buffer, (short) 0, (short) 8);
		apdu.setOutgoingAndSend((short) 0, (short) 8);
	}

	/*
	 * The GET DATA command is used to retrieve a primitive data object not
	 * encapsulated in a record within the current application.
	 * 
	 * The usage of GET DATA in this implementation is limited to the ATC,
	 * the PIN Try Counter, and the last online ATC.
	 */
	 //GET DATA 
	private void getData(APDU apdu, byte[] apduBuffer) {
		/*
		 * buffer[OFFSET_P1..OFFSET_P2] should contains of the following tags
		 *  9F36 - ATC 
		 *  9F17 - PIN Try Counter 
		 *  9F13 - Last online ATC 
		 *  9F4F - Log Format
		 */
		if (apduBuffer[ISO7816.OFFSET_P1] == (byte) 0x9F) {
			apduBuffer[0] = (byte) 0x9F;
			apduBuffer[1] = apduBuffer[ISO7816.OFFSET_P2];
			switch (apduBuffer[ISO7816.OFFSET_P2]) {
			// The apduBuffer[OFFSET_P1,OFFSET_P2] already contains the right Tag,
			// so we can write the Length and Value to the next bytes in the apduBuffer
			// and then send this.
			case 0x36: // ATC
				apduBuffer[ISO7816.OFFSET_P2 + 1] = (byte) 0x02; // length 2 bytes
				Util.setShort(apduBuffer, (short) (ISO7816.OFFSET_P2 + 2), protocolState.getATC()); // value
				// send the 5 byte long TLV for ATC
				apdu.setOutgoingAndSend(ISO7816.OFFSET_P1, (short) 5); 
				break;

			case 0x17: // PIN Try Counter
				apduBuffer[ISO7816.OFFSET_P2 + 1] = (byte) 0x01; // length 1 byte
				apduBuffer[ISO7816.OFFSET_P2 + 2] = pin.getTriesRemaining(); // value
				// send the 4 byte TLV for PIN Try counter
				apdu.setOutgoingAndSend(ISO7816.OFFSET_P1, (short) 4); 
				break;

			case 0x13: // Last online ATC
				apduBuffer[ISO7816.OFFSET_P2 + 1] = (byte) 0x02; // length 2 bytes
				Util.setShort(apduBuffer, (short) (ISO7816.OFFSET_P2 + 2), protocolState.getLastOnlineATC()); // value
				// send the 5 byte long TLV for last online ATC
				apdu.setOutgoingAndSend(ISO7816.OFFSET_P1, (short) 5);  
				break;
			case 0x4F: // Log Format - not supported yet
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
		}
	}

	private void readRecord(APDU apdu, byte[] buffer,byte[] aid) {
		
		staticData.readRecord(apdu, buffer,aid);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(buffer[1]+2));
		apdu.sendBytesLong(buffer, (short)0, (short)(buffer[1]+2));
	}

	private void getProcessingOptions(APDU apdu, byte[] response,byte[] aid) {
		// TODO Check APDU? PDOL is not checked at this moment
		
		// Return data using Format 1 
		response[0] = (byte) 0x80; // Tag
		response[1] = (byte) 0x06; // Length
		
		// 2 byte Application Interchange Profile 
		Util.setShort(response, (short)2, staticData.getAIP(aid)); 
		
		// 4 byte Application File Locator
		Util.arrayCopyNonAtomic(staticData.getAFL(aid), (short)0, response, (short)4, (short)4);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)8);
		apdu.sendBytesLong(response, (short)0, (short)8);	
		
		protocolState.setProcPerformed();
	}

	public void generateFirstAC(APDU apdu, byte[] apduBuffer,byte[] aid) {
		// First 2 bits of P1 specify the type
		// These bits also have to be returned, as the Cryptogram Information Data (CID);
		// See Book 3, Annex C6.5.5.4 
		byte cid = (byte) (apduBuffer[ISO7816.OFFSET_P1] & 0xC0);
		if (cid == RFU_CODE || cid == AAC_CODE) {
			// not a request for TC or ARQC
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		theCrypto.generateFirstACReponse(cid, apduBuffer, staticData.getCDOL1DataLength(), null, (short)0, response, (short)0,aid);
		protocolState.setFirstACGenerated(cid);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(response[1]+2));
		apdu.sendBytesLong(response, (short)0, (short)(response[1]+2));		
	}
 
	public void generateSecondAC(APDU apdu, byte[] apduBuffer,byte[] aid) {
		// First 2 bits of P1 specify the type
		// These bits also have to be returned, as the Cryptogram Information Data (CID);
		// See Book 3, Sect 6.5.5.4 of the Common Core Definitions.
		byte cid = (byte) (apduBuffer[ISO7816.OFFSET_P1] & 0xC0);
		if (cid == RFU_CODE || cid == ARQC_CODE) {
			// not a request for TC or AAC
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}	

		theCrypto.generateSecondACReponse(cid, apduBuffer, staticData.getCDOL2DataLength(), null, (short)0, response, (short)0,aid);
		protocolState.setSecondACGenerated(cid);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(response[1]+2));
		apdu.sendBytesLong(response, (short)0, (short)(response[1]+2));		
	}
}
