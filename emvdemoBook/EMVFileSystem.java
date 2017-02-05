package emvdemo;

import javacard.framework.*;

// Implementation of the EMV Card file system
// Class EMVfile defines a linear fixed-record file for storing
// EMV application data objects

public class EMVFileSystem {

	private byte[] selected_flag;
	private EMVFile[] files;
	private byte files_num; //Maximum number of files supported
	private byte next_av=0;//next file that can be created
	private byte selected_sfi;//SFI of the currently selected file
	
	public EMVFileSystem(byte maxfiles) {
		// TODO Auto-generated constructor stub
		files_num=maxfiles;
		files=new EMVFile[maxfiles];
		selected_flag=JCSystem.makeTransientByteArray((short)1,JCSystem.CLEAR_ON_RESET );
	}

	
	public void createFile(byte sfi, byte recnum, byte reclen) throws ISOException {
		// TODO Auto-generated method stub
		if (next_av==files_num)
			ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		
		files[next_av]=new EMVFile(sfi,recnum,reclen);
		next_av++;
	}
	
	public boolean selectFile(byte sfi)
	{
		byte i;
		
		for(i=0;i<next_av;i++)
			if (files[i].getSFI()==sfi)
			{
				selected_flag[0]=(byte)0xFF;
				selected_sfi=sfi;
				return true;
			}
		return false;
	}
	
	public EMVFileRecord readRecord(byte sfi,byte recnum) throws ISOException
	{
		
		byte i;
		boolean f=false;
		for(i=0;i<next_av;i++)
			if (files[i].getSFI()==sfi)
			{
				f=true;
				break;
			}
	
		if (!f) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);

		return files[i].readRecord((byte)(recnum-1)); //EMV rec num starts with 1 !!!
	}	
	
	public void writeRecord(byte sfi,byte recnum, byte[] value,byte len) throws ISOException
	{
		byte i;
		for(i=0;i<next_av;i++)
			if (files[i].getSFI()==sfi)
			{
				files[i].writeRecord((byte)(recnum-1), value, len);
				return;
			}
		
		ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
	}
}//class EMVFileSystem
