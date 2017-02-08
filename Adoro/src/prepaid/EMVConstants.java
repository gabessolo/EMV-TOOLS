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

import javacard.framework.*;

/* EMVConstants defines a constants used in the EMV standard and 
 * constants specific to this implementation. It extends ISO7816
 * as some ISO7816 constants are also used by EMV.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
  *
 */

public interface EMVConstants extends ISO7816 {

    // commands
    byte INS_GENERATE_AC = (byte) 0xAE;
    byte INS_GET_DATA = (byte) 0xCA;
    byte INS_GET_PROCESSING_OPTIONS = (byte) 0xA8;
    byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
    byte INS_VERIFY = (byte) 0x20;
    byte INS_GET_CHALLENGE = (byte) 0x84 ;
    byte INS_READ_RECORD = (byte) 0xB2;
    byte INS_GET_SK = (byte) 0xB9; // en esperant que cette commande n'est pas dans la norme EMV ou ISO7816
    
    // Already defined in ISO7816.java:
    //  INS_SELECT = A4
    //  INS_EXTERNAL_AUTHENTICATE = 82

    // post-issuance commands
    byte INS_APPLICATION_BLOCK = (byte)0x1E;
    byte INS_APPLICATION_UNBLOCK = (byte)0x18;
    byte INS_CARD_BLOCK = (byte)0x16;
    byte INS_PIN_CHANGE_UNBLOCK = (byte)0x24;

    // status words
    short SW_ISSUER_AUTHENTICATION_FAILED = (short)0x6300;

    // constants to record the (persistent) lifecycle state
    byte PERSONALISATION = (byte)0x00;
    byte READY = (byte)0x01;
    byte BLOCKED = (byte)0x02;

    /* codes for cryptogram types used in P1*/
    byte ARQC_CODE = (byte)0x80;
    byte   TC_CODE = (byte)0x40;
    byte  AAC_CODE = (byte)0x00;
    byte  RFU_CODE = (byte)0xC0;
    
    /* types of AC  */
    byte NONE = (byte)0x00;
    byte ARQC = (byte)0x01;
    byte   TC = (byte)0x02;
    byte  AAC = (byte)0x03;

    // types of CVM performed; NONE for none.
   byte PLAINTEXT_PIN = (byte)0x01;
   byte ENCRYPTED_PIN = (byte)0x02;
    
    //same as VISA or MASTERCARD
   byte CLS_ISO = (byte)0x00;
   byte CLS_MANUFACTURE=(byte)0x80;
    
   /* public final static byte[] pdol = new byte[]{
			(byte)0x83, // Read record message template
			 0x00 // Record length			
			};
    
    public final static byte[] pdol_visa=new byte[]{
    		(byte)0x83,
    		0x0B,
    		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    		};
    
    public final static byte[] CVM_List=new byte[] {
    		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    		0x5E,
    		0x03,0x1F,0x03
    		};*/
    
    /*
   byte COUNTRY_CODE=40;      //Austria
   short CURRENCY_CODE=(short)978;//euro
    //Maximum allowed transaction amount
   short MAX_TRANS_AMOUNT=(short)650;
    //Maximum allowed transaction amount
   short MAX_CUMUL_AMOUNT=(short)650;//

    //Application version number
   byte[] AVN={(byte)0x00,(byte)0x02};
    //EPI ICC a.p
   byte AVN_LEN=(byte)0x02;

    //Application usage control
   byte[] AUC={(byte)0xFF,(byte)0x00};
   byte AUC_LEN=(byte)0x02;

    //Application effective date (YYMMDD)
   byte[] AED={(byte)0x00,(byte)0x01,(byte)0x01};
   byte AED_LEN=(byte)0x03;

    //Application expiration date
   byte[] AXD={(byte)3,(byte)12,(byte)31};
   byte AXD_LEN=(byte)0x03;

    //Issuer country code
   byte[] ICD={(byte)0,(byte)COUNTRY_CODE};
   byte ICD_LEN=(byte)0x02;

    //Application currency code
   byte[] ACD={(byte)0x03,(byte)0xD2};
   byte ACD_LEN=(byte)0x02;

   //CardHolder name
   byte[] CHN={'G','.','A','B','E','S','S','O','L','O'};

   byte CHN_LEN=(byte)0xA0;
    
   byte[] DEMO_PIN={	(byte)0x24,(byte)0x12,(byte)0x34,
            						(byte)0xFF,(byte)0xFF,(byte)0xFF,
            						(byte)0xFF,(byte)0xFF
            					};*/
    
    byte PIN_TRY_LIMIT=3;
    byte PIN_MAX_LEN=2;
    
    byte SEQF_APP_SELECTED=3;
	byte SEQF_GETPROC_PERFORMED=4;
	byte SEQF_ARQC_GENERATED=5;
	byte SEQF_AAC_GENERATED=6;
}

//Processing restrictions
//http://www.openscdp.org/scripts/tutorial/emv/processingrestrictions.html
	
//TERMINAL RISK MANAGEMENT
//http://www.openscdp.org/scripts/tutorial/emv/terminalriskmanagement.html

// TERMINAL ACTION ANALYSIS
// http://www.openscdp.org/scripts/tutorial/emv/terminalactionanalysis.html

// CARD ACTION ANALYSIS
//http://www.openscdp.org/scripts/tutorial/emv/cardactionanalysis.html

/*
 CV Rule Byte 1
 Source: EMV Book 3 
  b8   b7   b6   b5   b4   b3   b2   b1   Meaning
  0  RFU
  0  Fail cardholder verification if this CVM is unsuccessful
  1  Apply succeeding CV Rule if this CVM is unsuccessful
  0  0  0  0  0  0  Fail CVM processing
  0  0  0  0  0  1  Plaintext PIN verification performed by ICC
  0  0  0  0  1  0  Enciphered PIN verified online
  0  0  0  0  1  1  Plaintext PIN verification performed by ICC and signature (paper)
  0  0  0  1  0  0  Enciphered PIN verification performed by ICC
  0  0  0  1  0  1  Encpihered PIN verification performed by ICC and signature (paper)
  0  x  x  x  x  x  Values in the range 000110-011101 reserved for future use by this specification
  0  1  1  1  1  0  Signature (paper)
  0  1  1  1  1  1  No CVM required
  1  0  x  x  x  x  Values in the range 100000-101111 reserved for use by the individual payment systems
  1  1  x  x  x  x  Values in the range 110000-111110 reserved for use by the issuer
  1  1  1  1  1  1  This value is not available for use
  
  CV Rule Byte 2
  Source: EMV Book 3 
  Value
Meaning
'00'  Always
  '01'  If unattended cash
  '02'  If not unattended cash and not manual cash and not purchase with cashback
  '03'  If terminal supports the CVM
  '04'  If manual cash
  '05'  If purchase with cashback
  '06'  If transaction is in the application currency and is under X value
  '07'  If transaction is in the application currency and is over X value
  '08'  If transaciton is in the application currency and is under Y value
  '09'  If transaciton is in the application currency and is over Y value
  '0A'-'7F'  RFU
  '80'-'FF'  Reserved for use by individual payment systems
  
 * */

