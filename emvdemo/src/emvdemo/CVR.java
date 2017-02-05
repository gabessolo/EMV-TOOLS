package emvdemo;

//class representative the CVR (card verification results objects) 
public class CVR {

	private byte[] bytes;
	
	public CVR()
	{
		bytes=new byte[4];
		bytes[0]=3; //CVR length is given in the first byte
	}
	
	public byte[] getBytes() {
		
		return bytes;
	}

	public byte getByte(byte n) {
	
		return bytes[n];
	}

	public void reset()
	{
		bytes[1]=0;
		bytes[2]=0;
		bytes[3]=0;
	}
	
	//method setPINPerformed, sets the "Offline PIN verification was performed"
	public void setPINPerformed()
	{
		//set bit 3 in byte 2
		bytes[1]=(byte)(bytes[1]|4);
	}
	
	//method setPINFailed, sets the "Offline PIN verification failed"
	public void setPINFailed()
	{
		//set bit 2 in byte 2
		bytes[1]=(byte)(bytes[1]|2);
	}
	
	public void setPINTryLimit()
	{
		//set bit 7 in byte 3
		bytes[2]=(byte)(bytes[2]|64);
	}
	
	//method setAACinGAC1, sets the "AAC returned in the first generate AC"
	public void setAACinGAC1() {
		//nothing to set, relevant bit are 0
		return;
	}

	//Method setGAC2notReq , sets the Second generate AC not requested 
	public void setGAC2notReq() {
		//set bit 8 in byte 2
		bytes[1]=(byte)(bytes[1]|128);
	}

	public void setTCinGAC1() {
		//set bit 5 in byte 2
		bytes[1]=(byte)(bytes[1]|16);
	}

	public void setMaxAmount() {
		bytes[3]=(byte)(bytes[3]|2);		
	}

}//class CVR
