package emvdemo;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EMVFileRecord {

	private byte rec_length; //maximum length of the record
	private byte act_length; //actual length of the data in the record
	
	private byte[] record_data;
	
	public EMVFileRecord(byte rl)
	{
		
		record_data=new byte[rl];
		rec_length=rl;
	}

	public void writeData(byte[] value,byte len)
	{
		JCSystem.beginTransaction();
		Util.arrayCopy(value,(short)0, record_data, (short)0, (short)len);
		act_length=len;
		JCSystem.commitTransaction();
		
	}
	
	public byte getRecordLen()
	{
		return rec_length;
	}
	
	public byte getActualLen() {
		// TODO Auto-generated method stub
		return act_length;
	}
	
	public byte[] getData() {
		// TODO Auto-generated method stub
		return record_data;
	}

}
