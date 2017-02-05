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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/* An object of this class is responsible for all crypto-related stuff.
 * It provides methods for computing Applications Cryptograms and
 * contains all the cryptographic keys needed for this.
 * 
 * One  design choice is whether the client passes the ATC (and maybe other data)
 * explicitly as parameters, or whether this object obtain them from the applet as needed.
 * We go for the latter approach. The former leads to a 'cleaner' interface, but with many
 * more parameters.
 * 
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 */

public class EMVCrypto implements EMVConstants {
	
	/* Reference back to the applet that uses this EMVCrypto object */
	private final SimpleEMVApplet theApplet;

	private final byte[]  sessionkey;
	
	/** 3DESKey ICC Master Key, shared with the bank  */
	private final DESKey mk;
	
	private final Cipher desCipher;
	private final Signature desMAC;
	
	/** 3DESKey session keys, derived from Master Key mk */
	private final DESKey sk;

	/** Scratchpad transient byte array for diversification data used to build session key */
	private final byte[] diversification_data;
	
	/** Transient byte array for storing ac transaction_data */
	byte[] transaction_data;
	
	public EMVCrypto(SimpleEMVApplet x){
		theApplet = x; // reference back to the applet

		diversification_data = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		sessionkey = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
		transaction_data = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
		
		desCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
		desMAC = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);
		
		mk = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
		mk.setKey(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 },
				(short) 0);
		sk = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
	}
	
	/* Sets the current 3DES session key, based on the Application Transaction Counter (ATC).
	 * 
	 * It is done as described in Book 2, Annex A1.3.1, by encrypting
	 *     ATC || F0 || 00 || 00 || 00 || 00 || 00  
	 *  with the card's 3DES Master Key to obtain the left 8 bytes, and encrypting
	 *     ATC || OF || 00 || 00 || 00 || 00 || 00  
	 *  with the card's 3DES Master Key to obtain the right 8 bytes. 
	 * */
	private void setSessionKey(){
		// as 8-byte diversification data we take the ATC followed by all zeroes
        Util.setShort(diversification_data, (short)0, theApplet.protocolState.getATC());
        Util.arrayFillNonAtomic(diversification_data, (short)2, (short)6, (byte)0);

        desCipher.init(mk, Cipher.MODE_ENCRYPT);

        //compute left 8 bytes of the session key
		diversification_data[2] = (byte)0xF0;
		desCipher.doFinal(diversification_data , (short)0, (short)8, sessionkey, (short)0);

		//compute right 8 byte  of the session key
		diversification_data[2] = (byte)0x0F;
		desCipher.doFinal(diversification_data, (short)0, (short)8, sessionkey, (short)0);

		sk.setKey(sessionkey, (short)0);
	}

	/*
	 * Computes a cryptogram, as described in Book 2, Sec 8.1, and stores it in the 
	 * given response buffer at the given offset.
	 * 
	 * The cryptogram is an 8 byte MAC over data supplied by the terminal 
	 * (as specified by the CDOL1 or CDOL2) and data provided by the ICC.
	 * 
	 * The data supplied by the terminal is in the ADPU buffer. This method does
	 * not need to know what this data is, ie. does not need to know the CDOLs, 
	 * but only needs to know the total length of these data elements. 
	 * 
	 * As data provided by the ICC this method just uses the minimum recommended 
	 * set of data elements, ie the AIP and ATC (see Book 2, Sect 8.1.1), for
	 * both the first and the second AC. Hence one method can be used for both.
	 * 
	 * @requires apduBuffer != response, to avoid problems overwriting the apduBuffer??
	 * 
	 * @param cid        the type of AC, ie. AAC_CODE, TC_CODE, or ARCQ_CODE
	 * @param apduBuffer contains the terminal-supplied data to be signed in the AC
	 * @param length     length of the terminal-supplied data 
	 * @param response   the destination array where the AC is stored at given offset
	 * @param offset     offset in this response array
	 */
	private void computeAC(byte cid, byte[] apduBuffer, short length, 
			byte[] response, short offset,byte[] aid){ 
		/* Collect the data to be MAC-ed in the array transaction_data */

		// Copy CDOL from the APDU buffer, at offset 0:
		Util.arrayCopy(apduBuffer, OFFSET_CDATA, transaction_data, (short)0, length);
		// 2 bytes AIP, at offset length:
		Util.setShort(transaction_data, length, theApplet.staticData.getAIP(aid));
		// 2 bytes ATC, at offset length + 2:
		Util.setShort(transaction_data, (short)(length+2), theApplet.protocolState.getATC());
 
		//TODO What is the following data? 
		//consulter ce lien pour la date et l'heure
		//https://www.geeketfier.fr/archives/bien-utiliser-la-date-et-lheure-en-java/
		transaction_data[(short)(length+4)] = (byte)0x80;   //T:Response Message Template Format 
		transaction_data[(short)(length+5)] = (byte)0x13;   //L
		
		transaction_data[(short)(length+6)] = (byte)0x9A;   	//Transaction Date
		transaction_data[(short)(length+7)] = (byte)0x03;
		transaction_data[(short)(length+8)] = (byte)0x00;
		transaction_data[(short)(length+9)] = (byte)0x00;
		transaction_data[(short)(length+10)]= (byte)0x00;
												
		transaction_data[(short)(length+11)] = (byte)0x9F; 	//Transaction Time
		transaction_data[(short)(length+12)] = (byte)0x21;
		transaction_data[(short)(length+12)] = (byte)0x03;
		transaction_data[(short)(length+13)] = (byte)0x00;
		transaction_data[(short)(length+14)] = (byte)0x00;
		transaction_data[(short)(length+15)] = (byte)0x00; 
												
		transaction_data[(short)(length+16)] = (byte)0x9C; 	//Transaction Type
		transaction_data[(short)(length+17)] = (byte)0x02;
		transaction_data[(short)(length+18)] = (byte)0x00;
		transaction_data[(short)(length+19)] = (byte)0x00;   
												
		transaction_data[(short)(length+20)] = (byte)0x5F2A;
		transaction_data[(short)(length+21)] = (byte)0x02;
		transaction_data[(short)(length+22)] = (byte)0x00;
		transaction_data[(short)(length+23)] = (byte)0x00; 	//Transaction reference currency code
		
		// contenu d'une transaction en provenance du terminal

		//9F02,0x06,0x00 		//Amount, Authorized (Numeric) Length:06
		//9F03,0x06,0x00  		//Amount, Other (Numeric) Length:06
		//9F1A,0x02,0x10,0xA 	//Terminal Country Code (Gabon)
		
		// MAC is a CBC-MAC computed according to ISO/IEC 9797-1, padding method 2
        desMAC.init(sk, Signature.MODE_SIGN);
	    desMAC.sign(transaction_data, (short)0, (short)(length+23), response, offset);
	 }

	/*
	 * Compute the first AC response APDU using Format 1. (See Book 3, Section 6.5.5.4.)
	 * This method also sets the session key.
	 * 
	 * The response contains the 
	 *  - CID: Cryptogram Information Data, 1 byte long
	 *  - ATC Application Transaction Counter, 2 bytes long
	 *  - AC: Application Cryptogram, 8 bytes long
	 *  - optionally, IAD:  Issuer Application Data, 30 bytes long
	 * 
	 * @param cid        the type of AC, ie. AAC_CODE, TC_CODE, or ARCQ_CODE
	 * @param apduBuffer contains the terminal-supplied data
	 * @param length     length of the terminal-supplied data
	 * @param iad        the IAD, or null, if IAD is omitted
	 * @param response   the destination array where the response is stored, at given offset
	 */
	public void generateFirstACReponse(byte cid, byte[] apduBuffer, short length, byte[] iad, short iad_length,
			                           byte[] response,  short offset,byte[] aid) 
	{
		setSessionKey();
		generateSecondACReponse(cid,apduBuffer,length, iad, iad_length, response, offset,aid);
	}
	
	/*
	 * Compute the second AC response APDU using Format 1. (See Book 3, Section 6.5.5.4.)
	 * 
	 */
	public void generateSecondACReponse(byte cid, byte[] apduBuffer, short length, byte[] iad, short iad_length,
                                        byte[] response,  short offset,byte[] aid) {
		response[offset] = (byte) 0x80; // Tag for Format 1 cryptogram

		if (iad==null) {
			// Length: 1 byte CID + 2 byte ATC + 8 byte AC = 11
			response[(short)(offset+1)] = (byte)11;  
		} else {
			// Length: 1 byte CID + 2 byte ATC + 8 byte AC + iad_length byte IAD
			response[(short)(offset+1)] = (byte)(11+iad_length);  
		}

		
		// 1 byte CID, ie the type of AC returned 
		response[(short)(offset+2)] = cid; 
		
		// 2 byte ATC, at offset 3:
		Util.setShort(response, (short)(offset+3), theApplet.protocolState.getATC()); 

		// the AC itself
		computeAC(cid, apduBuffer, length, response, (short)(offset+5),aid);

		// finally we get the (optional) IAD 
		if (iad!=null) {
			Util.arrayCopy(iad, (short)0, response, (short)(offset+13), (short)18);
		}

		// Force an IAD of 18 bytes consisting of all 0s
		// Needed for EMV-CAP reader
		response[(short)(offset+1)] = (byte)29;
		Util.arrayFillNonAtomic(response, (short)(offset+13), (short)18, (byte)0x0);
	}
	
}

//CardHolderVerification
//http://www.openscdp.org/scripts/tutorial/emv/cardholderverification.html

// DDA
//http://www.openscdp.org/scripts/tutorial/emv/dda.html

// SDA
/* source : http://www.openscdp.org/scripts/tutorial/emv/SDA.html
 * 
 * 
 * 
 * 
   SDA ensures the authenticity of ICC data. 
   After SDA it is sure that the data from the ICC is real and hasn't changed 
   by anyone. 
   But SDA doesn't assure the uniqueness of ICC data. 
   SDA is a digital signature scheme working with asymmetric cryptograhpy. 
   Asymmetric cryptography uses a pair of keys. 
   If you encode something with the first key, 
   you can only decode it with the second key. 
   The pair of keys is divided into a public and a private key. 
   With the private key the issuer can "sign" critical data on ICC.
   Only the issuer knows the private key. The public key is not secret. 
   Every terminal has the public key and can decode the signed data. 
   If it conforms to the specification the data is authentic and has not changed.
  
   The Static application data will be signed with the Issuer Private Key (S1) 
   and stored in Signed Application Data (SSAD). 
   The corresponding Issuer Public Key (P1) will be stored in the Issuer PK Certificate.
   To verify that S1 and P1 are made by the Issuer,
   the Issuer PK Certificate is signed with a Certification Authority Private Key (SCA). 
   The Certification Authority Public Key (PCA) is stored in the IC Terminal. 
   For SDA the terminals decrypt the Issuer PK Certificate with the PCA key.
   If the decryption was successful, 
   the terminal extracts the P1 key to decrypt the SSAD. 
   SDA was successful if the IC Terminal verifies the SSAD.
  
  */

