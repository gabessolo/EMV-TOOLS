package emvdemo;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException; 
import java.security.Key;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator; 
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec; 

public class EMVdemo extends Applet {

	private  EMVPurse emvPurse;
	
	public final static byte TRUE=1;
	public final static byte FALSE=0;
	
	private EMVdemo() {
		emvPurse=new EMVPurse();
		register();
	}

	public boolean select(APDU apdu)
	{
		return true;
	}
	
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
	
		new EMVdemo();
	}

	public void process(APDU apdu) throws ISOException {
		// TODO Auto-generated method stub
		byte[] buffer=apdu.getBuffer();
		byte[] response;
		byte sfi,rn,r1;
		short len;
		EMVFileRecord record; 
		
		if (selectingApplet())
		{
			//Modifying the flags
			emvPurse.sequenceFlag[EMV.SEQF_APP_SELECTED]=TRUE;
			emvPurse.sequenceFlag[EMV.SEQF_GETPROC_PERFORMED]=FALSE;
			emvPurse.sequenceFlag[EMV.SEQF_ARQC_GENERATED]=FALSE;
			emvPurse.sequenceFlag[EMV.SEQF_AAC_GENERATED]=FALSE;
			emvPurse.sequenceFlag[EMV.SEQF_PIN_PERFORMED]=FALSE;
			emvPurse.sequenceFlag[EMV.SEQF_PIN_VERIFIED]=FALSE;
			
			return;
		}
		
		switch(buffer[ISO7816.OFFSET_CLA])
		{
			case ISO7816.CLA_ISO7816:
			switch(buffer[ISO7816.OFFSET_INS])
			{
			case EMV.INS_SELECT:
				if (buffer[ISO7816.OFFSET_LC]<EMV.AID_MIN_LEN
					|| buffer[ISO7816.OFFSET_LC] > EMV.AID_MAX_LEN)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				
				if (buffer[ISO7816.OFFSET_P1] != EMV.P1_SELECT
						|| buffer[ISO7816.OFFSET_P2] != EMV.P2_SELECT)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					
				break;
			
			case EMV.INS_READ_RECORD:
				if (buffer[ISO7816.OFFSET_P1]==0)
					ISOException.throwIt(EMV.SW_FUNC_NSUPP);
				
				if ((buffer[ISO7816.OFFSET_P2] & 7)!=4)
					ISOException.throwIt(EMV.SW_FUNC_NSUPP);
				
				sfi=(byte)(buffer[ISO7816.OFFSET_P2] >>>3);
				rn=buffer[ISO7816.OFFSET_P1];
				
				record=emvPurse.readRecord(sfi,rn);
				r1=record.getActualLen();
				
				Util.arrayCopy(record.getData(), (short)0,buffer,(short)0,(short)r1);
				apdu.setOutgoingAndSend((short)0, (short)r1);
				break;
				
			case EMV.INS_VERIFY:
				if (buffer[ISO7816.OFFSET_P1] != EMV.P1_VERIFY
				|| buffer[ISO7816.OFFSET_P2] != EMV.P2_VERIFY)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
				if (buffer[ISO7816.OFFSET_LC] != EMV.LC_VERIFY)
							ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				
				emvPurse.sequenceFlag[EMV.SEQF_PIN_PERFORMED]=TRUE;
				emvPurse.sequenceFlag[EMV.SEQF_PIN_VERIFIED]=FALSE;
				
				if (emvPurse.getPINTriesRemaining()==0)
					ISOException.throwIt(EMV.SW_AUTHM_BLK);
				
				apdu.setIncomingAndReceive();
				
				if (emvPurse.checkPIN(buffer,(short)ISO7816.OFFSET_CDATA,EMV.PIN_MAX_LEN))
				{
					emvPurse.sequenceFlag[EMV.SEQF_PIN_VERIFIED]=TRUE;
					return;
				}else
					ISOException.throwIt(Util.makeShort(EMV.SW1_VER_FAILED, emvPurse.getPINTriesRemaining()));
				
				break;
			default:ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				break;
			}
			break;
			
			case EMV.CLA_MANUFACTURER:
				switch(buffer[ISO7816.OFFSET_INS])
				{
					case EMV.INS_GET_PROCESSING_OPTIONS:
						if (buffer[ISO7816.OFFSET_P1] != EMV.P1_GET_PROC_OPT
						|| buffer[ISO7816.OFFSET_P2] != EMV.P2_GET_PROC_OPT)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				
						if (buffer[ISO7816.OFFSET_LC] != EMV.LC_GET_PROC_OPT)
									ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
						
						if(emvPurse.sequenceFlag[EMV.SEQF_APP_SELECTED]!=TRUE ||
						emvPurse.sequenceFlag[EMV.SEQF_GETPROC_PERFORMED]==TRUE)
							ISOException.throwIt(EMV.SW_COND_NOTSAT);
						
						if (emvPurse.getATC()==EMV.ATC_MAX_VALUE)
							ISOException.throwIt(EMV.SW_REFD_INVALID);
						
						//increment the transaction counter
						emvPurse.incrementATC();
					
						//setting the sequenceFlag
						emvPurse.sequenceFlag[EMV.SEQF_GETPROC_PERFORMED]=TRUE;
						emvPurse.sequenceFlag[EMV.SEQF_ARQC_GENERATED]=FALSE;
						emvPurse.sequenceFlag[EMV.SEQF_AAC_GENERATED]=FALSE;
						
						//Preparing and sending the response
						buffer[0]=EMV.TAG_PROC_OPT;//T
						buffer[1]=(byte)0x0E;//L
						
						buffer[2]=EMV.TAG_AIP; //T
						buffer[3]=(byte)0x02; //L
						Util.arrayCopy(emvPurse.getAIP(), (short)0, buffer, (short)4,EMV.AIP_LEN);
						
						buffer[6]=EMV.TAG_AFL; //T
						buffer[7]=(byte)0x08; //L
						Util.arrayCopy(emvPurse.getAFL(), (short)0, buffer, (short)8,EMV.AFL_LEN);
						apdu.setOutgoingAndSend((short)0, (short)16);
						
						break;
						
					case EMV.INS_GENERATE_AC:
				
						len=(short)(buffer[ISO7816.OFFSET_LC] & 0x00FF);
						if (len!=apdu.setIncomingAndReceive())
							ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
						
						if (buffer[ISO7816.OFFSET_LC]!=EMV.LC_GAC)
							ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
						//Verify P2
						if (buffer[ISO7816.OFFSET_P2]!=EMV.P2_GENERATE_AC)
							ISOException.throwIt(EMV.SW_WRONG_P1P2);
						
						//Only TC or AAC requests are supported
						if ((buffer[ISO7816.OFFSET_P1]!=EMV.CODE_TC)
								&& (buffer[ISO7816.OFFSET_P1]!=EMV.CODE_AAC))
							ISOException.throwIt(EMV.SW_WRONG_P1P2);
						
						//Verify the transaction context
						if ( (emvPurse.sequenceFlag[EMV.SEQF_GETPROC_PERFORMED]==FALSE)
								|| (emvPurse.sequenceFlag[EMV.SEQF_AAC_GENERATED]==TRUE))
						//then returns condition of use are not satisfied
							ISOException.throwIt(EMV.SW_COND_NOTSAT);
						
						//if it is the second generate ac command ..
						if (emvPurse.sequenceFlag[EMV.SEQF_ARQC_GENERATED]==TRUE)
							//then returns condition of use are not satisfied
							ISOException.throwIt(EMV.SW_COND_NOTSAT);
						
						//Perform Card Risk Management and generate respective response
						response=emvPurse.processAC_I(buffer[ISO7816.OFFSET_P1],buffer,ISO7816.OFFSET_CDATA,buffer[ISO7816.OFFSET_LC]);
						Util.arrayCopy(response, (short)0, buffer,(short)0, (short)(response[1]+2));
						//reset sequence flags
						emvPurse.sequenceFlag[EMV.SEQF_GETPROC_PERFORMED]=FALSE;
						
						//send the response out
						apdu.setOutgoingAndSend((short)0, (short)(response[1]+2));
						break;
						
					default:
						ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
						break;
				}/// switch EMV INS
			default:ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				break;
		
		} // switch CLA
		} 
	}	 //end of EMVdemo class
