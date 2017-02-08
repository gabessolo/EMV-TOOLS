/**
 * 
 */
package emvdemo;

/**
 * @author Abessolo
 *
 */
public abstract interface EMV {

	//Object tags
	public final static byte TAG_RECORD =(byte)0x70;
	public final static byte TAG_PROC_OPT =(byte)0x77;
	public final static byte TAG_RESP =(byte)0x77;  /*????*/
	public final static byte TAG_AIP =(byte)0x82;
	public final static byte TAG_AFL =(byte)0x94;
	public final static byte TAG_CVM =(byte)0x8E;
	public final static short TAG_CHN =(short)0x5F20;
	public final static short TAG_ACD =(short)0x9F42;
	public final static short TAG_ICD =(short)0x5F28;
	public final static short TAG_AXD =(short)0x5F24;
	public final static short TAG_AED =(short)0x5F25;
	public final static short TAG_AUC =(short)0x9F07;
	public final static short TAG_AVN =(short)0x9F08;

	//Cryptogram information data
	public final static short TAG_CID =(short)0x9F27;
	public final static short TAG_ATC =(short)0x9F36;
	public final static short TAG_AC =(short)0x9F26;
	public final static short TAG_IAD =(short)0x9F10;
	
	//Issue application data

	//Length of fixed-length objects
	public final static byte LEN_CID =(byte)0x01;
	public final static byte LEN_ATC =(byte)0x02;
	public final static byte LEN_AC =(byte)0x08;
	public final static byte LEN_IAD =(byte)0x08;
	public final static byte LEN_GAC1 =(byte)0x1F;
	
	//Offsets in complex TLV objects 
	//Response to 1 Generate AC
	public final static byte OFFSET_CID=(byte)2;
	public final static byte OFFSET_ATC=(byte)6;
	public final static byte OFFSET_AC=(byte)11;
	public final static byte OFFSET_IAD=(byte)22;
	
	public final static byte OFFSET_TUN=(byte)25;
	//Offset of the terminal UN on CDOL1
	
	//Coding of P1 in Generate AC
	public final static byte CODE_TC=(byte)0x40; //TC
	public final static byte CODE_AAC=(byte)0x00; //AAC
	
	//Flags
	//Constants defining the flags location in the flag object SequenceFlag
	public final static  short SEQF_LENGTH=7; //Number of flags
	public final static byte SEQF_APP_SELECTED=0;//Application selected
	public final static byte SEQF_APP_INVALIDATED=1;
	//Application invalidated
	//GET PROCESSING OPTIONS was performed
	public final static byte SEQF_GETPROC_PERFORMED=2;
	//A first GENERATE AC was executed with an ARQC response
	public final static byte SEQF_ARQC_GENERATED=3;
	//A first GENERATE AC was executed with an AAC response
	//because the application was invalidated
	public final static byte SEQF_AAC_GENERATED=4;
	//The verify command was performed
	public final static byte SEQF_PIN_PERFORMED=5;
	//The verify command was successfully performed
	public final static byte SEQF_PIN_VERIFIED=6;
	
	//Class codes
	public final static byte CLA_ISO=(byte)0x00;
	public final static byte CLA_MANUFACTURER=(byte)0x80;
	
	//Instruction codes
	public final static byte INS_SELECT=(byte)0xA4;
	public final static byte INS_READ_RECORD=(byte)0xB2;
	public final static byte INS_GET_PROCESSING_OPTIONS=(byte)0xA8;
	public final static byte INS_VERIFY=(byte)0x20;
	public final static byte INS_GENERATE_AC=(byte)0xAE;
		
	//P1 codes
	public final static byte P1_SELECT=(byte)0x04;
	public final static byte P1_GET_PROC_OPT=(byte)0x00;
	public final static byte P1_VERIFY=(byte)0x00;
	
	//P2 codes
	public final static byte P2_SELECT=(byte)0x00;
	public final static byte P2_GET_PROC_OPT=(byte)0x00;
	public final static byte P2_VERIFY=(byte)0x80;
	public final static byte P2_GENERATE_AC=(byte)0x00;
	
	//Lc
	public final static byte LC_GET_PROC_OPT=(byte)0x02;
	public final static byte LC_VERIFY=(byte)0x08;
	public final static byte LC_GAC=(byte)0x20;
	
	//Error status bytes
	final static short SW_FILE_INVALID=(short)0x6283;
	//Selected file invalidated
	//Verification failed 0 retries
	final static short SW_VER_FAILED_0=(short)0x63C0;
	//Verification failed 1 retries
	final static short SW1_VER_FAILED_1=(short)0x63C1;
	//Verification failed 2 retries
	final static short SW_VER_FAILED_2=(short)0x63C2;
	final static byte  SW1_VER_FAILED=(byte)0x63;
	
	//State of non-volatile memory unchanged
	final static short SW_MEM_UNCH=(short)0x6400;
	final static short SW_MEM_FAILURE=(short)0x6581;//Memory failure
	final static short SW_WRONG_LEN=(short)0x6700;//Wrong lengths
    //Conditions of use not satisfied
	final static short SW_COND_NOTSAT=(short)0x6985;//Wrong lengths
	//Command incompatible with file organization
	final static short SW_COMM_INCOMP=(short)0x6981;//
	//Security status not satisfied
	final static short SW_SEC_NOTSAT=(short)0x6982;
	//Authentication method blocked
	final static short SW_AUTHM_BLK=(short)0x6983;
	//Reference Data invalidated
	final static short SW_REFD_INVALID=(short)0x6984;
	final static short SW_FUNC_NSUPP=(short)0x6A81; //Function not supported
	final static short SW_FILE_NFOUND=(short)0x6A82; // File not found
	final static short SW_REC_NFOUND=(short)0x6A83; // Record not found
	final static short SW_WRONG_P1P2=(short)0x6A86; //Incorrect P1 P2
	
	//Other constants
	final static byte AID_MAX_LEN=16;
	final static byte AID_MIN_LEN=5;
	final static short ATC_MAX_VALUE=(short)0xFFFF;
	final static byte PIN_TRY_LIMIT=3;
	final static byte PIN_MAX_LEN=8;
	final static short AIP_LEN=(short)2;
	final static short AFL_LEN=(short)8;
	final static byte GAC1_RESP_LEN=(byte)0x21;
	
	//Generate AC
	final static byte MESSAGE_LEN=(byte)40; //Length of the message-input to AC
	final static byte AC_LEN=(byte)8; //cryptogram length
	final static byte SKEY_LEN=(byte)8; //session key length
	final static byte MKEY_LEN=(byte)16; //master key length
	final static byte MAX_FILE_SIZE=(byte)30;//maximum possible file size
	final static byte NUMBER_LEN=(byte)6; //length of the long number in bytes
}
