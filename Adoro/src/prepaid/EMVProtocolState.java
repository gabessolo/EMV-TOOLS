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

/* Class to track the transient - ie. "session" - state of the EMV protocol,
 * as well as the persistent state.
 * 
 * This implementation is not secure in that it allows the ATC to overflow.
 * Also, it does not offer any support for blocking the card.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 *
 */

public class EMVProtocolState implements EMVConstants {
	
	/* Reference back to the applet that uses this EMVCrypto object */
	private  SimpleEMVApplet theApplet;
	private short atc=0x0;
	private short lastOnlineATC=0x0;
	private short cumulativeAmount=(short)0x0;        //cumulative transaction amount
    private boolean pinValidate=false;
    private short maxAmount=0x0;
    private short amount=0x0;
    private byte  pinTryLimit=0x0;
	
   
	/** 
	 * Volatile protocol state; records if CVM has been performed, and if ACs
	 * have been generated
	 */
	private  byte volatileState[];
	
    /** 
     * 2 byte Card Verification Results
     */
	private  byte[] cvr;

	public byte getFirstACGenerated() {
		return volatileState[1];
	}

	public void setFirstACGenerated(byte ACType) {
		volatileState[1] = ACType;
	}

	public byte getSecondACGenerated() {
		return volatileState[2];
	}

	public void setSecondACGenerated(byte ACType) {
		volatileState[2] = ACType;
	}

	public byte getCVMPerformed() {
		return volatileState[0];
	}

	public void setCVMPerformed(byte CVMType) {
		volatileState[0] = CVMType;
	}
	

	public short getATC() {
		return atc;
	}

	private void increaseATC() {
		//if (atc == MAX) { BLOCK THIS CARD!! }, but we ignore security here
		atc = (short)(atc+1);
	}
	
	public short getLastOnlineATC() {
		return lastOnlineATC;
	}
	
	public EMVProtocolState(SimpleEMVApplet x){
		theApplet = x;
		volatileState = JCSystem.makeTransientByteArray((short) 7, JCSystem.CLEAR_ON_DESELECT);
		cvr = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
	}
	
	/* Starts a new session. This resets all session data and increases the ATC,
	 * but does not generate a session key yet.
	 */
	public void startNewSession(){
		setFirstACGenerated(NONE);
		setSecondACGenerated(NONE);
		setCVMPerformed(NONE);
		increaseATC();
		initPinTry();
	}
	
	/* 
	 * Sets the last online ATC equal to the current ATC
	 */
	public void onlineSessionCompleted(){
		lastOnlineATC = atc;
	}

	/* Returns the 4 byte CVR (Card Verification Results).
	 * Details are described in Book 3, Annex C7.3 */
	public byte[] getCVR() {
		return null;
	}
	
	public void setAmount(short amount)
	{
		this.amount=amount;
	}
	
	public short getAmount()
	{
		return amount;
	}
	
	public boolean getPINValidate()
	{
		return pinValidate;
	}
	
	public void setPINFailed()
	{
		pinValidate=false;
	}
	
	public void setPINValidate()
	{
		pinValidate=true;
	}

	public void initPinTry()
	{
		pinTryLimit=0x0;	
	}
	
	public byte getPinTry()
	{
		return pinTryLimit;	
	}
	
	public byte incrPinTry()
	{
		return pinTryLimit++;	
	}
	
	public void setAppSelected()
	{
		volatileState[SEQF_APP_SELECTED]=1;
	}
	
	public byte getAppSelected()
	{
		return volatileState[SEQF_APP_SELECTED];
	}
	
	public void setProcPerformed()
	{
		volatileState[SEQF_GETPROC_PERFORMED]=1;
	}
	
	public byte getProcPerformed()
	{
		return volatileState[SEQF_GETPROC_PERFORMED];
	}
}
