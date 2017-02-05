/* 
---- * Copyright (C) 2011  Digital Security group, Radboud University
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
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.ISO7816;

/* Class to record all the static data of an EMV applet, ie. the card details that
 * do not change over time (such as PAN, expiry date, etc.), with the exception
 * of the cryptographic keys.
 * 
 * This static data is organised in the simplest possible way, using some public byte
 * arrays to record exact APDUs that the card has to produce.
 * 
 * This class does not offer personalisation support - everything is hard-coded.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 *
 */

public class EMVStaticData implements EMVConstants {
	//<77 0E 82 02 38 00 94 08 08 01 05 00 10 01 02 01>;
	
	private final short theAIP_pse = 0x3800; // AIP
	private final short theAIP_maestro = 0x3800; // AIP
	private final byte[] theAFL_pse = new byte[]{ (byte)0x08, 0x01, 0x01, 0x00}; // AFL
	private final byte[] theAFL_maestro = new byte[]{ (byte)0x08, 0x01, 0x05, 0x00,0x10, 0x01, 0x02, 0x01}; // AFL
	
	byte[] PSE=new byte[] {0x31, 0x50, 0x41 , 0x59 , 0x2E , 0x53 , 0x59 , 0x53 , 0x2E , 0x44 , 0x44 , 0x46 , 0x30 , 0x31};
	
	
	byte[] AID_MAESTRO=new byte[] {(byte)0xA0 , 0x00 , 0x00 , 0x00 , 0x04 , 0x30 , 0x60};
			
	//private final short theAIP = 0x5800; // AIP
	//private final byte[] theAFL = new byte[]{ (byte)0x08, 0x01, 0x04, 0x01}; // AFL 
	//-AFL:  # Application File Locator, Tag 0x94
	   // - S1:  # AFL Record
	   //    B01: "40" # SFI [xxxxx___]  // 8
	   //    B02: "01" # From record  // 1
	   //    B03: "01" # To record  // 1
	   //    B04: "01" # First hashed
	   // - S2:  # AFL Record
	   //    B01: "48" # SFI [xxxxx___]  // 9
	   //    B02: "01" # From record  // 1
	   //    B03: "03" # To record  // 3
	   //    B04: "01" # First hashed  // 1
	   // - S3:  # AFL Record
	   //    B01: "50" # SFI [xxxxx___]  // 10
	   //    B02: "01" # From record  // 1
	   //    B03: "03" # To record  // 3
	   //    B04: "01" # First hashed
	
	/** Returns the 4 byte AFL (Application File Locator)  */
	public byte[] getAFL(byte[] aid){
		
		if (0==Util.arrayCompare(aid,(short)0,PSE,(short)0,(short) PSE.length))
			return theAFL_pse;
		else if (0==Util.arrayCompare(aid,(short)0,AID_MAESTRO,(short)0,(short) AID_MAESTRO.length))
			return theAFL_maestro;
		
		return theAFL_maestro;
	}
	
	/** Returns the 2 byte AIP (Application Interchange Profile) 
	 *  See Book 3, Annex C1 for details
	 *   */
	public short getAIP(byte[] aid) {
		
		if (0==Util.arrayCompare(aid,(short)0,PSE,(short)0,(short) PSE.length))
			return theAIP_pse;
		else if (0==Util.arrayCompare(aid,(short)0,AID_MAESTRO,(short)0,(short) AID_MAESTRO.length))
			return theAIP_maestro;
		
		return theAIP_maestro;
		
		
		
		//- AIP:  # Application Interchange Profile, Tag 0x82
	    //   B01: "78"
					 //# 1_______ - bit 8, Always 0
					 //# _1______ - bit 7, SDA supported
					 //# __1_____ - bit 6, DDA supported
					 //# ___1____ - bit 5, Cardholder verification is supported
					 //# ____1___ - bit 4, Terminal Risk Management is to be performed
					 //# _____1__ - bit 3, Issuer Authentication is supported
        			 //# _______1 - bit 1, Combined DDA/AC Generation is supported
		//	B02: "00" # RFU
	}
	
	private final byte[]  fci_pse   = new byte[]{ 
			0x6F,0x20 ,(byte)0x84 ,0x0E ,0x31 ,0x50 ,0x41 ,0x59 ,0x2E ,0x53 ,0x59 ,0x53 ,0x2E ,0x44 ,0x44 ,0x46
			,0x30 ,0x31 ,(byte)0xA5 ,0x0E ,(byte)0x88 ,0x01 ,0x01 ,0x5F ,0x2D ,0x04 ,0x72 ,0x75 ,0x65 ,0x6E ,(byte)0x9F ,0x11
			,0x01 ,0x01
             
	};
     
	private final byte[] sfi1_pse = new byte[]{
			0x70 ,0x1E ,0x61 ,0x1C ,0x4F ,0x07 ,(byte)0xA0 ,0x00 ,0x00 ,0x00 ,0x04 ,0x30 ,0x60 ,0x50 ,0x07 ,0x4D
			,0x61 ,0x65 ,0x73 ,0x74 ,0x72 ,0x6F ,(byte)0x9F ,0x12 ,0x07 ,0x4D ,0x61 ,0x65 ,0x73 ,0x74 ,0x72 ,0x6F		
	};
	
    /*
	// File for EMV-CAP
	private final byte[] record3 = new byte[]{	
			0x70, // Read record message template
			0x00, // Record length
			(byte)0x8C, 0x21, (byte)0x9F, 0x02, 0x06, (byte)0x9F, 0x03, 0x06, (byte)0x9F, 0x1A, 0x02, (byte)0x95, 0x05, 0x5F, 0x2A, 0x02, (byte)0x9A, 0x03, (byte)0x9C, 0x01, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x35, 0x01, (byte)0x9F, 0x45, 0x02, (byte)0x9F, 0x4C, 0x08, (byte)0x9F, 0x34, 0x03, // Card Risk Management Data Object List 1 
			(byte)0x8D, 0x0C, (byte)0x91, 0x0A, (byte)0x8A, 0x02, (byte)0x95, 0x05, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x4C, 0x08, // Card Risk Management Data Object List 2
			0x5A, 0x05, 0x12, 0x34, 0x56, 0x78, (byte)0x90, // 5A Primary account number			
			(byte)0x8E, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Cardholder Verification Method (CVM) List (Always transaction_data PIN performed by ICC) 
			(byte)0x9F, 0x55, 0x01, (byte)0x80, // Unknown field
			(byte)0x9F, 0x56, 0x0C, 0x00, 0x00, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Bit filter
			};
 	*/
	
	// File for EMV
	/*
	private final byte[] record2 = new byte[]{
			0x70, // Read record message template
			0x00, // Record length
			// Mandatory data objects
			0x5F, 0x24, 0x03, // Application Expiry Date
			0x5A, 0x05, 0x12, 0x34, 0x56, 0x78, (byte)0x90, // 5A Primary account number
			(byte)0x8C, 0x21, (byte)0x9F, 0x02, 0x06, (byte)0x9F, 0x03, 0x06, (byte)0x9F, 0x1A, 0x02, (byte)0x95, 0x05, 0x5F, 0x2A, 0x02, (byte)0x9A, 0x03, (byte)0x9C, 0x01, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x35, 0x01, (byte)0x9F, 0x45, 0x02, (byte)0x9F, 0x4C, 0x08, (byte)0x9F, 0x34, 0x03, // Card Risk Management Data Object List 1
			(byte)0x8D, 0x18, (byte)0x91, 0x0A, (byte)0x8A, 0x02, (byte)0x95, 0x05, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x4C, 0x08, // Card Risk Management Data Object List 2
			// Other data
			(byte)0x8E, 0x02, 0x01, 0x00, // Cardholder Verification Method (CVM) List (Always transaction_data PIN performed by ICC)
			(byte)0x9F, 0x4A, 0x01, (byte)0x82, // Static Data Authentication Tag List
			};
 	*/
	

	/*
	private final byte[] record1 = new byte[]{
			0x70, // Read record message template
			(byte)0x8B, // Record length,
			(byte)0x8F, 0x01,0x00, // Certification Authority Public Key Index
			(byte)0x90, (byte)0x80, (byte)0x9A,0x67,(byte)0xF9,(byte)0xF5,(byte)0xB3,(byte)0xDA,0x20,0x6B,(byte)0xEC,(byte)0xE3,
									(byte)0xA9,0x2F,(byte)0x86,(byte)0xDE,0x2C,0x55,0x52,(byte)0xD0,0x6B,0x05,
									0x4A,0x51,(byte)0xC9,0x1E,(byte)0xB3,0x58,(byte)0x8C,0x46,0x1F,(byte)0xEB,
									0x24,(byte)0xAE,(byte)0x92,0x04,(byte)0xD7,0x4B,(byte)0xA2,(byte)0xD6,0x57,(byte)0xDE,
									0x4A,(byte)0x88,(byte)0xF7,(byte)0xDC,(byte)0xBA,(byte)0xBC,0x3D,0x23,0x5C,0x01,
									(byte)0xE0,(byte)0x9F,(byte)0xF0,0x37,0x72,0x64,(byte)0xA7,(byte)0xD6,0x52,0x77,
									0x7A,0x3E,0x2B,0x2D,0x78,0x08,0x7C,(byte)0x9A,(byte)0xB6,(byte)0x93,
									0x58,(byte)0xF9,0x1C,0x04,0x0D,0x59,0x7B,(byte)0x8C,(byte)0x87,0x5B,
									0x47,(byte)0x85,0x44,0x5B,(byte)0xCA,(byte)0xDF,(byte)0xF0,0x78,(byte)0xBA,0x67,
									(byte)0xE6,(byte)0xBA,(byte)0xFC,0x1B,0x01,0x04,0x2F,(byte)0xB3,(byte)0xBD,0x67,
									(byte)0xD9,0x38,0x02,(byte)0xA3,0x1D,0x30,(byte)0xBD,(byte)0xBE,0x31,0x44,
									(byte)0xA5,(byte)0xD5,0x0A,0x30,(byte)0x89,(byte)0xE3,(byte)0xD7,0x19,0x46,0x5F,
									(byte)0xB1,(byte)0xA2,0x07,(byte)0xB9,(byte)0xB9,0x24,(byte)0xF3,(byte)0xAF, // ICC Public Key Certificate (The Modulus it is a  supposition)
			(byte)0x90,0x32, 0x03, 0x10,0x00,0x01, // ICC Public Key Exponent
			(byte)0x92, 0x00, 0x00, // ICC Public Key Remainder
			(byte)0x9F, 0x49, 0x03, (byte)0x9F, 0x37, 0x04 // Dynamic Data Authentication Data Object List (DDOL)
			
			//0x5F,(byte)0x47,	 	//Message reference 	  	  	  	  	  	  	  	 
			//(byte)0x5F,0x48, 		//Cardholder private key 	  	  	  	  	  	  	  	 
			//(byte)0x5F,0x49, 		//Cardholder public key 	  	  	  	  	  	  	  	 
			//(byte)0x5F,0x4A, 		//Public key of certification authority
	};
	
    */
	//7056905C12096A1A87A5F4E0D5827011FB17E97A783835BC79C0EF57CABC21977...
	private final byte[] record_maestro_ing_tijdelijke_betalpas=new byte[] {
			0x70,(byte)0x56,
			(byte)0x90,(byte)0x54,	// ICC Public Key Certificate
			///
			(byte)0x12, (byte)0x09 , (byte)0x6A , (byte)0x1A , (byte)0x87 , (byte)0xA5 , (byte)0xF4 , (byte)0xE0 , (byte)0xD5 , (byte)0x82 , (byte)0x70 , (byte)0x11 , (byte)0xFB , (byte)0x17 , (byte)0xE9 , (byte)0x7A, 
			(byte)0x78, (byte)0x38 , (byte)0x35 , (byte)0xBC , (byte)0x79 , (byte)0xC0 , (byte)0xEF , (byte)0x57 , (byte)0xCA , (byte)0xBC , (byte)0x21 , (byte)0x97 , (byte)0x7B , (byte)0xD1 , (byte)0xED , (byte)0xEC,  
			(byte)0xC3, (byte)0x0E , (byte)0x51 , (byte)0xB4 , (byte)0x14 , (byte)0xC4 , (byte)0xC3 , (byte)0x9F , (byte)0xC9 , (byte)0x37 , (byte)0xBF , (byte)0x9F , (byte)0x86 , (byte)0x4E , (byte)0xEC , (byte)0x3D,  
			(byte)0xD1, (byte)0x10 , (byte)0x39 , (byte)0x93 , (byte)0x35 , (byte)0x69 , (byte)0x96 , (byte)0x61 , (byte)0xC1 , (byte)0x90 , (byte)0x3A , (byte)0xB4 , (byte)0xFA , (byte)0xA2 , (byte)0x5D , (byte)0x5B,  
			(byte)0x63, (byte)0xFA , (byte)0x42 , (byte)0x54 , (byte)0xDC , (byte)0xF1 , (byte)0xA6 , (byte)0x96 , (byte)0x4D , (byte)0xD8 , (byte)0x75 , (byte)0x50 , (byte)0x7B , (byte)0x1D , (byte)0x69 , (byte)0x65,  
			
			(byte)0x94, (byte)0x54 , (byte)0xEC , (byte)0x74, 
			
	};
	//70658F01059F320103927008D10BE4B8186D50...
	private final byte[] record_maestro_ing_tijdelijke_betaalpas2=new byte[] {
			
			0x70,(byte)0x65,
			(byte)0x8F,0x01,// Certification Authority Public Key Index
			    0x05,                          
			(byte)0x9F,0x32,0x01, //Issuer Public Key Exponent
				0x03,                          
			(byte)0x92,(byte)0x5C,// ICC Public Key Remainder

			////
			(byte)0x08, (byte)0xD1 , (byte)0x0B , (byte)0xE4 , (byte)0xB8 , (byte)0x18 , (byte)0x6D , (byte)0x50 , (byte)0x5E , (byte)0x1D , (byte)0x3F , (byte)0xD6,  
			(byte)0x30, (byte)0xA5 , (byte)0x44 , (byte)0xAC , (byte)0x64 , (byte)0x99 , (byte)0xFA , (byte)0x92 , (byte)0x5A , (byte)0xAE , (byte)0x49 , (byte)0x2D , (byte)0xF0 , (byte)0xA7 , (byte)0xC1 , (byte)0xA9, 
			(byte)0xD1, (byte)0xAB , (byte)0x9D , (byte)0xB2 , (byte)0x99 , (byte)0x57 , (byte)0x16 , (byte)0x73 , (byte)0xA7 , (byte)0x31 , (byte)0x3E , (byte)0x26 , (byte)0xBA , (byte)0xBA , (byte)0xEA , (byte)0x08,  
			(byte)0x17, (byte)0x9C , (byte)0xC7 , (byte)0x15 , (byte)0x85 , (byte)0x9D , (byte)0x6F , (byte)0x1C , (byte)0x30 , (byte)0xF8 , (byte)0xF1 , (byte)0xD8 , (byte)0x4A , (byte)0x9C , (byte)0x9E , (byte)0xFB, 
			(byte)0x3A, (byte)0xC2 , (byte)0x5E , (byte)0x9F , (byte)0x2D , (byte)0x06 , (byte)0x7E , (byte)0x61 , (byte)0x3E , (byte)0x31 , (byte)0x40 , (byte)0x2C , (byte)0x5F , (byte)0xDB , (byte)0xA7 , (byte)0x74,  
			(byte)0x09, (byte)0xA4 , (byte)0x40 , (byte)0x9A , (byte)0xEB , (byte)0xD9 , (byte)0xB0 , (byte)0x42 , (byte)0x2E , (byte)0xFF , (byte)0x31 , (byte)0x8B , (byte)0x0C , (byte)0x85 , (byte)0x94 , (byte)0xB1
			
	};
	//704E61154F07A000000004306050074D41455354524F
	private final byte[] record_maestro_ing_tijdelijke_betaalpas3=new byte[] {
     0x70 ,0x4E,
  0x61 ,0x15,
    0x4F, 0x07,
    (byte)0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60,
    0x50 ,0x07,
    (byte)0x4D, 0x41, 0x45, 0x53, 0x54, 0x52, 0x4F,//MAESTRO
    (byte)0x87 ,0x01,
    (byte)0x02,                                               
  0x61 ,0x1D,
    0x4F ,0x07,
    (byte)0xA0, 0x00, 0x00, 0x00, 0x04, (byte)0x80, 0x02,
    0x50 ,0x0F,
    (byte)0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x43, 0x6F, 0x64, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68,     //SecureCode Auth
    (byte)0x87 ,0x01,
      	0x00,                                               
  0x61 ,0x16,
    0x4F ,0x07,
    (byte)0xA0, 0x00, 0x00, 0x03, 0x15, 0x60, 0x20,                              
    0x50 ,0x08,
      0x43, 0x68, 0x69, 0x70, 0x6B, 0x6E, 0x69, 0x70,                          //Chipknip
      (byte)0x87 ,0x01,
      0x01   
	};
	
	private final byte[] record_maestro_ing_tijdelijke_betaalpas4=new byte[] {
		     0x70 ,(byte)0xE0,
		     	0x61,(byte)0xC0,
		     		0x5F,0x50,0x09,0x31,0x32,0x37,0x2e,0x30,0x2e,0x30,0x2e,0x31 //Issuer URL
	};
	
/*  maetro.emu 	
    =========
    
    name  = <31 50 41 59 2E 53 59 53 2E 44 44 46 30 31>;
    fci   = <6F 20 84 0E 31 50 41 59 2E 53 59 53 2E 44 44 46
             30 31 A5 0E 88 01 01 5F 2D 04 72 75 65 6E 9F 11
             01 01>;
    sfi1  = <70 1E 61 1C 4F 07 A0 00 00 00 04 30 60 50 07 4D
             61 65 73 74 72 6F 9F 12 07 4D 61 65 73 74 72 6F>;
};
{
    name  = <A0 00 00 00 04 30 60>;
    fci   = <6F 31 84 07 A0 00 00 00 04 30 60 A5 26 50 07 4D
             61 65 73 74 72 6F 5F 2D 04 72 75 65 6E 9F 11 01
             01 9F 12 07 4D 61 65 73 74 72 6F BF 0C 05 9F 4D
             02 0B 0A>;
    gpo   = <77 0E 82 02 38 00 94 08 08 01 05 00 10 01 02 01>;
    sfi1  = <70 41 57 12 67 61 96 00 02 94 00 34 14 D1 61 12
             26 00 18 70 79 67 5F 20 1A 4D 4F 4D 45 4E 54 55
             4D 2F 20 20 20 20 20 20 20 20 20 20 20 20 20 20
             20 20 20 9F 1F 0D 30 30 30 30 30 30 37 39 36 37
             31 38 37>,
            <70 81 93 90 81 90 2F 54 26 B3 7A 7B 04 FC 58 7B
             75 AF 4B D3 89 F8 30 28 12 DA 92 C9 ED C0 3B 07
             AD 04 9F 56 CB 6A E6 CB 21 C2 55 F7 CE 6A F8 3F
             7D 0F 57 6A 3D 85 A1 FD B6 9D BA E1 DB 6F EE F2
             4F 00 DC 78 D8 28 F7 41 65 23 7E C2 EF 75 0F 33
             C0 84 A1 22 B3 78 ED 69 B1 48 35 17 51 3E 74 05
             C9 B5 05 1C B1 CE 7E 2F EC 55 72 17 FE E3 74 AC
             59 3E D8 84 C6 08 F1 D2 6A D4 A0 59 7D 3A DF 57
             28 2B 5B 18 AA 4B FE 65 4D 5B 0D B7 62 72 54 17
             CC BF 5A 3B 27 38>,
            <70 41 9F 32 01 03 92 24 C1 D7 8B 85 FB 98 66 3D
             3C E7 65 3F 8C 94 78 DE 27 C7 67 7F 45 4C DE DD
             80 0D 6D 78 89 31 66 F9 E6 5F 5B 8F 9F 47 01 03
             9F 48 0A AB 52 D7 48 6A 14 27 B3 65 F5 9F 49 03
             9F 37 04>,
            <70 03 8F 01 04>,
            <70 81 94 9F 46 81 90 46 4E 31 90 7C E4 D5 2A A3
             FE 33 92 3D A6 B6 E1 79 EF D7 56 A7 E5 14 CB D0
             F9 B2 CE E3 9D 89 99 0C 7F B2 31 C6 EA BF 23 CA
             DA C5 00 8E BB 94 CA F8 15 01 45 10 01 9A 76 76
             B4 3C 4E 5D C3 39 BA 37 EB 04 D6 E9 74 21 C0 3E
             34 79 91 70 FF 52 A1 24 B6 ED 57 B7 DF 9F 1B 9D
             BA 2B 60 25 56 6E 6D B0 18 B5 D2 BD 01 DD 67 3C
             94 55 45 1B 3E 80 1B 35 34 00 91 F2 0F DB 59 E8
             A2 21 93 35 19 A6 DD 39 B6 4D 84 47 BC 6C 90 17
             03 AF 02 0F 7A 19 ED>;
    sfi2  = <70 81 86 5F 25 03 13 11 01 5F 24 03 16 11 30 5A
             09 67 61 96 00 02 94 00 34 14 5F 34 01 01 8E 12
             00 00 00 00 00 00 00 00 42 01 02 04 44 03 01 03
             02 00 9F 07 02 FF C0 9F 0D 05 B8 50 BC 80 00 9F
             0E 05 00 00 00 00 00 9F 0F 05 B8 70 BC 98 00 9F
             4A 01 82 5F 28 02 06 43 8C 21 9F 02 06 9F 03 06
             9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F
             35 01 9F 45 02 9F 4C 08 9F 34 03 8D 0C 91 0A 8A
             02 95 05 9F 37 04 9F 4C 08>,
            <70 0A 9F 08 02 00 02 9F 42 02 06 43>;
	  sfi11 = <00 00 00 00 00 00 00 06 43 14 02 01 00 20 20 00
                 03 22 00 00>,
                <40 00 00 00 00 00 00 00 00 14 02 01 00 1E 60 10
                 03 22 00 00>,
                <40 00 00 00 00 00 00 06 43 14 02 01 00 1D 60 10
                 03 22 00 00>,
                <40 00 00 00 05 00 00 06 43 14 02 01 00 1C 60 10
                 03 22 00 00>,
                <40 00 00 00 08 00 00 06 43 14 01 31 00 1B 60 10
                 03 22 00 00>,
                <40 00 00 00 00 00 00 06 43 14 01 31 00 18 60 10
                 03 22 00 00>,
                <40 00 00 00 00 01 00 06 43 14 01 31 00 17 60 10
                 03 22 00 00>,
                <40 00 00 00 00 01 00 06 43 14 01 31 00 16 60 10
                 03 22 00 00>,
                <40 00 00 00 04 00 00 06 43 14 01 31 00 15 60 10
                 03 22 00 00>,
                <40 00 00 00 00 00 70 06 43 14 01 31 00 14 60 10
                 03 22 00 00>;
        data9f17 = <9F 17 01 03>;
        data9f4f = <9F 4F 11 9F 27 01 9F 02 06 5F 2A 02 9A 03 9F 36
                 02 9F 52 06>;

	*/
	
	private final byte[]  fci_maestro   = new byte[]{ 
			0x6F, 0x31 , (byte)0x84 , 0x07 , (byte)0xA0 , 0x00 , 0x00 , 0x00 , 0x04 , 0x30 , 0x60 , (byte)0xA5 , 0x26 , 0x50 , 0x07 , 0x4D
			, 0x61 , 0x65 , 0x73 , 0x74 , 0x72 , 0x6F , 0x5F , 0x2D , 0x04 , 0x72 , 0x75 , 0x65 , 0x6E , (byte)0x9F , 0x11 , 0x01
			, 0x01 , (byte)0x9F , 0x12 , 0x07 , 0x4D , 0x61 , 0x65 , 0x73 , 0x74 , 0x72 , 0x6F , (byte)0xBF , 0x0C , 0x05 , (byte)0x9F , 0x4D
			, 0x02 , 0x0B , 0x0A
    };
    
	private final byte[]  gpo_maestro   = new byte[]{ 
		//77 0E 82 02 38 00 94 08 08 01 05 00 10 01 02 01	
            
	};
	
	private final byte[] sfi1_maestro = new byte[]{
			0x70 , 0x41 , 0x57 , 0x12 , 0x67 , 0x61 , (byte)0x96 , 0x00 , 0x02 , (byte)0x94 , 0x00 , 0x34 , 0x14 , (byte)0xD1 , 0x61 , 0x12
			, 0x26 , 0x00 , 0x18 , 0x70 , 0x79 , 0x67 , 0x5F , 0x20 , 0x1A , 0x4D , 0x4F , 0x4D , 0x45 , 0x4E , 0x54 , 0x55
			, 0x4D , 0x2F , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20 , 0x20
			, 0x20 , 0x20 , 0x20 , (byte)0x9F , 0x1F , 0x0D , 0x30 , 0x30 , 0x30 , 0x30 , 0x30 , 0x30 , 0x37 , 0x39 , 0x36 , 0x37
			, 0x31 , 0x38 , 0x37
	};
	
	private final byte[] sfi2_maestro = new byte[]{0x70 , (byte)0x81 , (byte)0x93 ,(byte) 0x90 , (byte)0x81 , (byte)0x90 , 0x2F , 0x54 , 0x26 , (byte)0xB3 , 0x7A , 0x7B , 0x04 , (byte)0xFC , 0x58 , 0x7B
			, 0x75 , (byte)0xAF , 0x4B , (byte)0xD3 , (byte)0x89 , (byte)0xF8 , 0x30 , 0x28 , 0x12 , (byte)0xDA , (byte)0x92 , (byte)0xC9 , (byte)0xED , (byte)0xC0 , 0x3B , 0x07
			, (byte)0xAD , 0x04 , (byte)0x9F , 0x56 , (byte)0xCB, 0x6A , (byte)0xE6 , (byte)0xCB , 0x21 , (byte)0xC2 , 0x55 , (byte)0xF7 , (byte)0xCE , 0x6A , (byte)0xF8 , 0x3F
			, 0x7D , 0x0F , 0x57 , 0x6A , 0x3D , (byte)0x85 , (byte)0xA1 , (byte)0xFD , (byte)0xB6 , (byte)0x9D , (byte)0xBA , (byte)0xE1 , (byte)0xDB , 0x6F , (byte)0xEE , (byte)0xF2
			, 0x4F , 0x00 , (byte)0xDC , 0x78 , (byte)0xD8 , 0x28 , (byte)0xF7 , 0x41 , 0x65 , 0x23 , 0x7E , (byte)0xC2 , (byte)0xEF , 0x75 , 0x0F , 0x33
			, (byte)0xC0 , (byte)0x84 , (byte)0xA1 , 0x22 , (byte)0xB3 , 0x78 , (byte)0xED , 0x69 , (byte)0xB1 , 0x48 , 0x35 , 0x17 , 0x51 , 0x3E , 0x74 , 0x05
			, (byte)0xC9 , (byte)0xB5 , 0x05 , 0x1C , (byte)0xB1 , (byte)0xCE , 0x7E , 0x2F , (byte)0xEC , 0x55 , 0x72 , 0x17 , (byte)0xFE , (byte)0xE3 , 0x74 , (byte)0xAC
			, 0x59 , 0x3E , (byte)0xD8 , (byte)0x84 , (byte)0xC6 , 0x08 , (byte)0xF1 , (byte)0xD2 , 0x6A , (byte)0xD4 , (byte)0xA0 , 0x59 , 0x7D , 0x3A , (byte)0xDF , 0x57
			, 0x28 , 0x2B , 0x5B , 0x18 , (byte)0xAA , 0x4B , (byte)0xFE , 0x65 , 0x4D , 0x5B , 0x0D , (byte)0xB7 , 0x62 , 0x72 , 0x54 , 0x17
			, (byte)0xCC , (byte)0xBF , 0x5A , 0x3B , 0x27 , 0x38
	};
            
	private final byte[] sfi3_maestro = new byte[]{0x70 , 0x41 , (byte)0x9F , 0x32 , 0x01 , 0x03 , (byte)0x92 , 0x24 , (byte)0xC1 , (byte)0xD7 , (byte)0x8B , (byte)0x85 , (byte)0xFB , (byte)0x98 , 0x66 , 0x3D
			, 0x3C , (byte)0xE7 , 0x65 , 0x3F , (byte)0x8C , (byte)0x94 , 0x78 , (byte)0xDE , 0x27 , (byte)0xC7 , 0x67 , 0x7F , 0x45 , 0x4C , (byte)0xDE , (byte)0xDD
			, (byte)0x80 , 0x0D , 0x6D , 0x78 , (byte)0x89 , 0x31 , 0x66 , (byte)0xF9 , (byte)0xE6 , 0x5F , 0x5B , (byte)0x8F , (byte)0x9F , 0x47 , 0x01 , 0x03
			, (byte)0x9F , 0x48 , 0x0A , (byte)0xAB , 0x52 , (byte)0xD7 , 0x48 , 0x6A , 0x14 , 0x27 , (byte)0xB3 , 0x65 , (byte)0xF5 , (byte)0x9F , 0x49 , 0x03
			, (byte)0x9F , 0x37 , 0x04
	};
            
	private final byte[] sfi4_maestro = new byte[]{0x70, 0x03, (byte)0x8F, 0x01, 0x04
			
	};
           
	private final byte[] sfi5_maestro = new byte[]{0x70 , (byte)0x81 , (byte)0x94 , (byte)0x9F , (byte)0x46 , (byte)0x81 , (byte)0x90 , 0x46 , 0x4E , (byte)0x31 , (byte)0x90 , (byte)0x7C , (byte)0xE4 , (byte)0xD5 , (byte)0x2A , (byte)0xA3
			, (byte)0xFE , (byte)0x33 , (byte)0x92 , (byte)0x3D , (byte)0xA6 , (byte)0xB6 , (byte)0xE1 , (byte)0x79 , (byte)0xEF , (byte)0xD7 , (byte)0x56 , (byte)0xA7 , (byte)0xE5 , (byte)0x14 , (byte)0xCB , (byte)0xD0
			, (byte)0xF9 , (byte)0xB2 , (byte)0xCE , (byte)0xE3 , (byte)0x9D , (byte)0x89 , (byte)0x99 , 0x0C , (byte)0x7F , (byte)0xB2 , (byte)0x31 , (byte)0xC6 , (byte)0xEA , (byte)0xBF , (byte)0x23 , (byte)0xCA
			, (byte)0xDA , (byte)0xC5 , (byte)0x00 , (byte)0x8E , (byte)0xBB , (byte)0x94 , (byte)0xCA , (byte)0xF8 , 0x15 , 0x01 , 0x45 , 0x10 , (byte)0x01 , (byte)0x9A , 0x76 , 0x76
			, (byte)0xB4 , 0x3C , 0x4E, (byte)0x5D , (byte)0xC3 , (byte)0x39 , (byte)0xBA , (byte)0x37 , (byte)0xEB , (byte)0x04 , (byte)0xD6 , (byte)0xE9 , 0x74 , (byte)0x21 , (byte)0xC0 , 0x3E
			, 0x34 ,(byte)0x79 , (byte)0x91 ,(byte)0x70 , (byte)0xFF , (byte)0x52 , (byte)0xA1 , (byte)0x24 , (byte)0xB6 , (byte)0xED , (byte)0x57 , (byte)0xB7 , (byte)0xDF , (byte)0x9F , (byte)0x1B , (byte)0x9D
			, (byte)0xBA , 0x2B , 0x60 , 0x25 , 0x56 , 0x6E , (byte)0x6D , (byte)0xB0 , (byte)0x18 , (byte)0xB5 , (byte)0xD2 , (byte)0xBD , (byte)0x01 , (byte)0xDD , 0x67 , 0x3C
			, (byte)0x94 , 0x55 , 0x45 , 0x1B ,(byte)0x3E , (byte)0x80 , 0x1B , 0x35 , 0x34 , 0x00 , (byte)0x91 , (byte)0xF2 , (byte)0x0F , (byte)0xDB , (byte)0x59 , (byte)0xE8
			, (byte)0xA2 , (byte)0x21 , (byte)0x93 , 0x35 , (byte)0x19 , (byte)0xA6 , (byte)0xDD , 0x39 , (byte)0xB6 , (byte)0x4D , (byte)0x84 , (byte)0x47 , (byte)0xBC , (byte)0x6C , (byte)0x90 , 0x17
			, (byte)0x03 , (byte)0xAF , 0x02 , 0x0F , 0x7A , (byte)0x19 , (byte)0xED
	};

	
	/** Return the length of the data specified in the CDOL1 
	 * 
	 */
	public short getCDOL1DataLength() {
		return 0x2B;
	}

	/** Return the length of the data specified in the CDOL2 
	 * 
	 */
	public short getCDOL2DataLength() {
		return 0x1D;
	}
	
	public byte[] getFCI(byte[] aid) {
		
		if (0==Util.arrayCompare(aid,(short)0,PSE,(short)0,(short) PSE.length))
			return fci_pse;
		else if (0==Util.arrayCompare(aid,(short)0,AID_MAESTRO,(short)0,(short) AID_MAESTRO.length))
			return fci_maestro;
		
		return fci_maestro; 
	}

	public short getFCILength(byte[] aid) {
		
		if (0==Util.arrayCompare(aid,(short)0,PSE,(short)0,(short) PSE.length))
			return (short)fci_pse.length;
		else if (0==Util.arrayCompare(aid,(short)0,AID_MAESTRO,(short)0,(short) AID_MAESTRO.length))
			return (short)fci_maestro.length;
		
		return (short)fci_maestro.length;
	}
	
	/** Provide the response to INS_READ_RECORD in the response buffer
	 * 
	 */
	public void readRecord(APDU apdu, byte[] response,byte[] aid){
		
		byte[] apduBuffer=apdu.getBuffer();
		
		
		if (0==Util.arrayCompare(aid,(short)0,PSE,(short)0,(short) PSE.length))
		{
			if(apduBuffer[ISO7816.OFFSET_P2] ==0x0C && apduBuffer[ISO7816.OFFSET_P1] == 0x01) 
			{ // SFI PSE
				Util.arrayCopy(sfi1_pse, (short)0, response, (short)0, (short)sfi1_pse.length);
				response[1] = (byte)(sfi1_pse.length - 2); 
			}else {
				// File does not exist
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			}
		}else if (0==Util.arrayCompare(aid,(short)0,AID_MAESTRO,(short)0,(short) AID_MAESTRO.length))
		{
			
			if(apduBuffer[ISO7816.OFFSET_P2] ==0x0C && apduBuffer[ISO7816.OFFSET_P1] == 0x01) 
			{ // SFI 1
				Util.arrayCopy(sfi1_maestro, (short)0, response, (short)0, (short)sfi1_maestro.length);
				response[1] = (byte)(sfi1_maestro.length - 2); 
			}
			else if(apduBuffer[ISO7816.OFFSET_P2] == 0x0C && apduBuffer[ISO7816.OFFSET_P1] == 0x02) 
			{ // SFI 2
				Util.arrayCopy(sfi2_maestro, (short)0, response, (short)0, (short)sfi2_maestro.length);
				response[1] = (byte)(sfi2_maestro.length - 2); 
			}
			else if(apduBuffer[ISO7816.OFFSET_P2] == 0x0C && apduBuffer[ISO7816.OFFSET_P1] == 0x03) 
			{ // SFI 3
				Util.arrayCopy(sfi3_maestro, (short)0, response, (short)0, (short)sfi3_maestro.length);
				response[1] = (byte)(sfi3_maestro.length - 2); 
				
			}else if(apduBuffer[ISO7816.OFFSET_P2] == 0x0C && apduBuffer[ISO7816.OFFSET_P1] == 0x04) 
			{ // SFI 4
				Util.arrayCopy(sfi4_maestro, (short)0, response, (short)0, (short)sfi4_maestro.length);
				response[1] = (byte)(sfi4_maestro.length - 2); 
			
			}else if(apduBuffer[ISO7816.OFFSET_P2] == 0x0C && apduBuffer[ISO7816.OFFSET_P1] == 0x05) 
			{ // SFI 5
				Util.arrayCopy(sfi5_maestro, (short)0, response, (short)0, (short)sfi5_maestro.length);
				response[1] = (byte)(sfi5_maestro.length - 2); 
			
			}
			else {
				// File does not exist
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			}
		}
	}
}


