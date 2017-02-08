package emvdemo;

import javacard.framework.*;
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



public class EMVPurse {

	public final static byte TRUE=1;
	public final static byte FALSE=0;
	
	//Definition of the application-related constants and objects
	
	private final static byte FILES_NUMBER=10;	//number of files supported
	private final static byte RECORDS_NUMBER=15;//number of records in a file
	private final static byte RECORD_LENGTH=64;	//record length
	private final static byte COUNTRY_CODE=40;	//Austria
	private final static short CURRENCY_CODE=(short)978;//euro
	//Maximum allowed transaction amount
	private final static short MAX_TRANS_AMOUNT=(short)650;
	//Maximum allowed transaction amount
	private final static short MAX_CUMUL_AMOUNT=(short)650;//
	
	//Application version number
	private final static byte[] AVN={(byte)0x00,(byte)0x02};
	//EPI ICC a.p
	private final static byte AVN_LEN=(byte)0x02;
	
	//Application usage control
	private final static byte[] AUC={(byte)0xFF,(byte)0x00};
	private final static byte AUC_LEN=(byte)0x02;
	
	//Application effective date (YYMMDD)
	private final static byte[] AED={(byte)0x00,(byte)0x01,(byte)0x01};
	private final static byte AED_LEN=(byte)0x03;
	
	//Application expiration date
	private final static byte[] AXD={(byte)3,(byte)12,(byte)31};
	private final static byte AXD_LEN=(byte)0x03;
	
	//Issuer country code
	private final static byte[] ICD={(byte)0,(byte)COUNTRY_CODE};
	private final static byte ICD_LEN=(byte)0x02;
	
	//Application currency code
	private final static byte[] ACD={(byte)0x03,(byte)0xD2};
	private final static byte ACD_LEN=(byte)0x02;
	
	//CardHolder name
	private final static byte[] CHN={'A','b','e','s','s','o','l','o',
									 ' ',
									 'G','a','e','t','a','n'};
	
	private final static byte CHN_LEN=(byte)15;
	
	//Cardholder verification method list
	private final static byte[] CVM={0x00,0x00,0x00,0x00, //no X
									 0x00,0x00,0x00,0x00, //no Y
									 0x41,0x03}; //off-line plaintext PIN
	
	private final static byte CVM_LEN=(byte)10;
	
	//
	
	//EMV application specific values 
	//AIP, dynamic off-line auth, CHV
	private final byte[] AIP={0x5C,0x00};
	
	//AFL, two AEFs with SFIs 1 and 2
	private final byte[] AFL={  (byte)0x08,(byte)0x01,
								(byte)0x06,(byte)0x00,
								(byte)0x10,(byte)0x01,
								(byte)0x02,(byte)0x00
								};
							  	
	private final byte[] DEMO_PIN={(byte)0x24,(byte)0x12,(byte)0x34,
									(byte)0xFF,(byte)0xFF,(byte)0xFF,
									(byte)0xFF,(byte)0xFF};
	
	//Card Issuer Action Code - Decline
	private final byte[] CIACD={(byte)0x00,(byte)0x02,(byte)0x40,(byte)0x02};

	//master key value for the cryptogram calculation
	private final byte[] MKac_VALUE={ (byte)0x01,(byte)0x33,(byte)0x02,(byte)0x11,
										(byte)0x01,(byte)0x33,(byte)0x02,(byte)0x11,
										(byte)0x11,(byte)0x33,(byte)0x02,(byte)0x01,
										(byte)0x11,(byte)0x33,(byte)0x02,(byte)0x01};
	
	//Application elementary files descriptors
	public final byte AEF1=1;
	public final byte AEF2=2;

/*----------------------------------------------------------------*/
	
	//Internal data objects
	private EMVFileSystem filesystem; 			//Application filesystem
	private short ATC=(short)0;					//Application transaction counter
	private short cumulativeAmount=(short)0;	//cumulative transaction amount
	private OwnerPIN emvPIN;					//EMV card application PIN object
	private CVR appCVR;							//CVR object
	byte[] sequenceFlag=null;					//Application sequence flag
	private byte[] message;						//Input to AC calculation
	private byte[] cryptogram;					
	private byte[] SKl,SKr;						//Session keys L and R
	private byte[] rand;						//random number for session key derivation
	
	
	private SecretKey desKey;				
	private SecretKey des3Key;				
	
	
	private CipherDES cipherDES;				//DES cipher
	private CipherDES cipherDES3;				//DES3 cipher
	
	private byte[] record;
	private byte[] GAC1_result;
	private short amount;
	
	
	/*--------------------------------------------*/
	
	//class constructor
	public EMVPurse()
	{
	//Create transient sequence flg object
	sequenceFlag=JCSystem.makeTransientByteArray(EMV.SEQF_LENGTH, JCSystem.CLEAR_ON_RESET);
	//Create Application pin object
	emvPIN=new OwnerPIN(EMV.PIN_TRY_LIMIT,EMV.PIN_MAX_LEN);
	emvPIN.update(DEMO_PIN,(short)0, (byte)8);
	//Create cipher key objects
	desKey=(new CipherDES()).getSecretKey(false);
	des3Key=(new CipherDES()).getSecretKey(false);
	
	
	appCVR=new CVR();
	
	message=new byte[EMV.MESSAGE_LEN];
	rand=new byte[EMV.SKEY_LEN];
	SKl=new byte[EMV.SKEY_LEN];
	SKr=new byte[EMV.SKEY_LEN];
	
	cryptogram=new byte[EMV.AC_LEN];
	record=new byte[RECORD_LENGTH];
	GAC1_result=new byte[EMV.GAC1_RESP_LEN];
	
	//Creating the file system and files
	filesystem=new EMVFileSystem(FILES_NUMBER);
	
	filesystem.createFile(AEF1,(byte)6,RECORD_LENGTH);
	filesystem.createFile(AEF2,(byte)2,RECORD_LENGTH);
	
	//Putting EMV TLV objects into files
	//Mandatory data AEF1
	record=fillEMVRecord(EMV.TAG_AVN,AVN_LEN,AVN);
	filesystem.writeRecord(AEF1,(byte)1,record,(byte)(record[1]+2));
	
	record=fillEMVRecord(EMV.TAG_AUC,AUC_LEN,AUC);
	filesystem.writeRecord(AEF1,(byte)2,record,(byte)(record[1]+2));
	
	record=fillEMVRecord(EMV.TAG_AED,AED_LEN,AED);
	filesystem.writeRecord(AEF1,(byte)3,record,(byte)(record[1]+2));
	
	record=fillEMVRecord(EMV.TAG_AXD,AXD_LEN,AXD);
	filesystem.writeRecord(AEF1,(byte)4,record,(byte)(record[1]+2));
	
	record=fillEMVRecord(EMV.TAG_ICD,ICD_LEN,ICD);
	filesystem.writeRecord(AEF1,(byte)5,record,(byte)(record[1]+2));
	
	record[1]=(byte)(CVM_LEN+2);
	record[2]=EMV.TAG_CVM;
	record[3]=CVM_LEN;
	
	Util.arrayCopy(EMVPurse.CVM,(short)0, record, (short)4, CVM_LEN);
	filesystem.writeRecord(AEF1,(byte)6,record,(byte)(record[1]+2));
	
	//Optional data AEF2
	record=fillEMVRecord(EMV.TAG_CHN,CHN_LEN,CHN);
	filesystem.writeRecord(AEF2,(byte)1,record,(byte)(record[1]+2));
	
	record=fillEMVRecord(EMV.TAG_ACD,ACD_LEN,ACD);
	filesystem.writeRecord(AEF2,(byte)2,record,(byte)(record[1]+2));
	
	}//constructor
	
	/* --------------------------------------*/
	
	//Methods
	
	//core method for application cryptogram generation
	public byte[] processAC_I(byte request, byte[] cdata, byte offset, byte len) {
		// 
		short status;
		byte action;
		byte cid;
		
		//Reset the CVR
		appCVR.reset();
		
		//perform card risk management and card action analysis
		action=riskManagement(request,cdata,offset,len);
		
		//Fill T and L of the response
		GAC1_result[0]=EMV.TAG_RESP;
		GAC1_result[1]=EMV.LEN_GAC1;
		
		//Fill cryptogram information data
		GAC1_result[EMV.OFFSET_CID]=(byte)(EMV.TAG_CID >> 8);
		GAC1_result[EMV.OFFSET_CID+1]=(byte)((EMV.TAG_CID <<8)>>> 8);
		GAC1_result[EMV.OFFSET_CID+2]=(byte)EMV.LEN_CID ;
		
		cid=action;
		
		byte b=(byte)(appCVR.getByte((byte)2) & CIACD[2]);
		if (b == CIACD[2]) //pin try limit exceeded
			cid=(byte)(cid|2); // set bit 2
		
		
		GAC1_result[EMV.OFFSET_CID+3]=cid;
		
		//fill ATC
		GAC1_result[EMV.OFFSET_ATC]=(byte)(EMV.TAG_ATC>>8);
		GAC1_result[EMV.OFFSET_ATC+1]=(byte)((EMV.TAG_ATC<<8)>>8);
		GAC1_result[EMV.OFFSET_ATC+2]=EMV.LEN_ATC;
		GAC1_result[EMV.OFFSET_ATC+3]=(byte)(ATC>>8);
		GAC1_result[EMV.OFFSET_ATC+4]=(byte)((ATC << 8)>>8);
		
		//prepare the cryptogram message
		Util.arrayCopy(cdata,ISO7816.OFFSET_CDATA,message, (short)0, (short)29);
		Util.arrayCopy(AIP,(short)0,message, (short)29,(short)2);
		Util.setShort(message, (short)31, ATC);
		Util.arrayCopy(appCVR.getBytes(),(short)0,message,(short)33,(short)4);
		
		//pad the message according to ISO/IEC 9797, method 2
		message[37]=(byte)0x80;
		message[38]=(byte)0;
		message[39]=(byte)0;
		
		//derive session keys
		//first prepare the input for the key derivation function
		Util.setShort(rand , (short)0, ATC);
		rand[2]=(byte)0; rand[3]=(byte)0;
		Util.arrayCopy(cdata, (short)(ISO7816.OFFSET_CDATA+EMV.OFFSET_TUN), rand, (short)4, (short)4);
		
		
		
		derive_SKl(cipherDES3,rand,SKl);
		derive_SKr(cipherDES3,rand,SKr);
		
		//compute cryptogram
		compute_ac(message,EMV.MESSAGE_LEN,SKl,SKr,cipherDES,desKey,cryptogram);
		
		//fill cryptogram in
		GAC1_result[EMV.OFFSET_AC]=(byte)(EMV.TAG_AC>>8);
		GAC1_result[EMV.OFFSET_AC+1]=(byte)((EMV.TAG_AC <<8) >>8);
		GAC1_result[EMV.OFFSET_AC+2]=(byte)EMV.LEN_AC;
		Util.arrayCopy(cryptogram,(short)0, GAC1_result, (short)(EMV.OFFSET_AC+3), (short)EMV.AC_LEN);
		
		//fill issuer Application data
		GAC1_result[EMV.OFFSET_IAD]=(byte)(EMV.TAG_IAD>>8);
		GAC1_result[EMV.OFFSET_IAD+1]=(byte)((EMV.TAG_IAD <<8) >>8);
		GAC1_result[EMV.OFFSET_IAD+2]=(byte)EMV.LEN_IAD;
		GAC1_result[EMV.OFFSET_IAD+3]=(byte)1; //key derivation index
		GAC1_result[EMV.OFFSET_IAD+4]=(byte)1; //cryptogram version number
		
		Util.arrayCopy(appCVR.getBytes(),(short)0, GAC1_result, (short)(EMV.OFFSET_IAD+5), (short)4);
		
		return GAC1_result;
	}//process AC_I

	//Derivation of the left part of the session key
	private void derive_SKl(CipherDES cipher,byte[] input,byte[] output)
	{
		input[2]=(byte)0xF0;
		output=cipher.encrypt(input,false);
		return;
	}//derive_SKl
	
	//Derivation of the left part of the session key
	private void derive_SKr(CipherDES cipher,byte[] input,byte[] output)
	{
		input[2]=(byte)0x0F;
		output=cipher.encrypt(input,false);
		return;
	}//derive_SKr
	
	private void compute_ac(byte[] message, byte mesLen, byte[] KeyL, byte[] KeyR, CipherDES cipher, 
			SecretKey key,
			byte[] ac) {
		
		byte rounds,j,i;
		
		rounds=(byte)(mesLen/8);
		
		for(i=0;i<8;i++)
			ac[i]=message[i];
		for(j=1;j<(byte)(rounds+1);j++) {
			cipher.encrypt(ac, false);
			if (j!=rounds)
				for(i=0;i<8;i++)
					ac[i]=(byte)(ac[i]^message[(byte)(j*8+i)]);
		}
		
		cipher.encrypt(ac, false);
		return;
	} //compute_ac
	
	//Card risk management routine
	private byte riskManagement(byte request, byte[] cdata, byte offset, byte len) {
	
		byte action;
		byte[] cvrBytes;
		
		//if AAC was requested the card answers with AAC
		//or if any other from TC was requested - answer with AAC
		if (request==EMV.CODE_AAC || request!=EMV.CODE_TC)
		{
			//set relevant CVR bits
			appCVR.setGAC2notReq();
			appCVR.setAACinGAC1();
			
			return EMV.CODE_AAC;
		}
		
		//Card risk management functions
		//PIN verification status function
		if (sequenceFlag[EMV.SEQF_PIN_PERFORMED]==TRUE)
			appCVR.setPINPerformed(); //VERIFY command was given during the transaction
		
		if (sequenceFlag[EMV.SEQF_PIN_VERIFIED]==FALSE && sequenceFlag[EMV.SEQF_PIN_PERFORMED]==TRUE)
			appCVR.setPINFailed(); //PIN verification failed 
		
		if (emvPIN.getTriesRemaining()==0)
			appCVR.setPINTryLimit();//PIN Try Limit exceeded
		
		//Maximum ofline transaction amount  check function
		amount=Util.makeShort(cdata[offset+4], cdata[offset+5]);
		
		//if the amount exceed the maximum
		if (Util.makeShort(cdata[offset+19],cdata[offset+20])==CURRENCY_CODE && amount>MAX_TRANS_AMOUNT)
			appCVR.setMaxAmount();
		
		//check that higher digits of the Amount field are 00
		if (cdata[offset]!=0 ||
				cdata[offset+1]!=0 || 
				cdata[offset+2]!=0 ||
				cdata[offset+3]!=0 )
			appCVR.setMaxAmount();
				
		//Maximum cumulative amount check function
		//if native currency transaction
		if (Util.makeShort(cdata[offset+19],cdata[offset+20])==CURRENCY_CODE && (amount+cumulativeAmount)>MAX_TRANS_AMOUNT)
			appCVR.setMaxAmount();
						
		//Perform Card action analysis
		
		//Verify the CVR against CIAC-decline
		cvrBytes=appCVR.getBytes();
		
		if (((cvrBytes[1] & CIACD[1])==CIACD[1]) || // Pin verification failed
			((cvrBytes[2] & CIACD[2])==CIACD[2]) || // Pin try limit exceeded
			((cvrBytes[3] & CIACD[3])==CIACD[3]) || // Upper consecutive or Accuulative amount exceeded 
			  sequenceFlag[EMV.SEQF_PIN_PERFORMED]==FALSE)
		{
			//set relevant CVR bits
			appCVR.setGAC2notReq();
			appCVR.setAACinGAC1();
			
			action=EMV.CODE_AAC;  // --decline transaction
			
		}else
		{
			if (Util.makeShort(cdata[offset+19], cdata[offset+20])==CURRENCY_CODE)
				cumulativeAmount=(short)(cumulativeAmount+amount);
			
				//set relevant CVR bits
				appCVR.setGAC2notReq();
				appCVR.setTCinGAC1();
				
				action=EMV.CODE_TC; //complete transaction (issue TC) 
		}
		
		return action;
	}//card risk management
	
	private byte[] fillEMVRecord(short t, byte l, byte[] v) {
		
		byte[] rec=new byte[EMVPurse.RECORD_LENGTH];
		
		rec[0]=EMV.TAG_RECORD;
		rec[1]=(byte)(l+3);
		rec[2]=(byte)(t>>8);
		rec[3]=(byte)((t<<8) >> 8);
		rec[4]=l;
		
		Util.arrayCopy(v, (short)0, rec, (short)5, (short)l);
		return rec;

	} //fillEMVRecord

	
	public byte[] getAIP() {
		return AIP;
	}

	public void incrementATC() {
		++ATC;
	}

	public byte[] getAFL() {
		return AFL;
	}

	public short getATC() {
		return ATC;
	}

	public EMVFileRecord readRecord(byte sfi, byte recnum) {
		return filesystem.readRecord(sfi, recnum);
	}

	public byte getPINTriesRemaining() {
		return emvPIN.getTriesRemaining();
	}

	public boolean checkPIN(byte[] buffer, short offset, byte len) {
		return emvPIN.check(buffer,offset,len);
	}
}// class EMVPurse
