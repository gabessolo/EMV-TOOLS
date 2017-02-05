package emvdemo;

import javacard.framework.*;



public class EMVFile {

	private byte rec_number;  //number of records in the file
	private EMVFileRecord[] file_records; //records themselves
	private byte _SFI;
	
	public EMVFile(byte sfi,byte rn,byte rl) throws ISOException
	{
		byte i;
		
		if (rn > EMV.MAX_FILE_SIZE)
			ISOException.throwIt(EMV.SW_MEM_FAILURE);
	
		_SFI=sfi;
		
		file_records=new EMVFileRecord[rn];
	
		for(i=0;i<rn;i++)
			file_records[i]=new EMVFileRecord(rl);
	
		rec_number=rn;
	}
	
	public byte getSFI()
	{
		
		return _SFI;
	}
	
	public EMVFileRecord readRecord (byte recnum) throws ISOException
	{
		if (recnum > rec_number-1)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	
		return file_records[recnum];
	}
	
	public void writeRecord(byte recnum, byte[] value,byte len) throws ISOException
	{
		if (recnum > rec_number-1)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		if (len > file_records[recnum].getRecordLen()-1) 
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	
		file_records[recnum].writeData(value,len);
	}
	
	public byte getRecordsNum()
	{
		return rec_number;
	}
}
