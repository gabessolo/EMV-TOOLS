package emvdemo;


import java.io.*;
import sun.misc.*;
import java.util.*;

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


public class CipherDES {

public static SecretKey myDesKey=null; 
public static final byte[] ckey= {//0x6E,0x04,0x0B,0x46,0x45,0x64,0x5D,0x37,
				  0x6A,0x03,0x0B,0x41,0x41,0x34,0x5D,0x37
				 };
			
public CipherDES()
{

}

public static SecretKey getSecretKey(boolean newkey)
{
	if (myDesKey!=null)
		return myDesKey;

	
	if (newkey==true)
	{
		try{
		myDesKey = KeyGenerator.getInstance("DES").generateKey();
		byte[] data=myDesKey.getEncoded();	

		for (byte theByte : data)
		{
  			System.out.println(Integer.toHexString(theByte));
		}

		
		SecretKey key2 = new SecretKeySpec(data, 0, data.length, "DES");
		
		return key2;
	
		}catch(NoSuchAlgorithmException e)
		{ e.printStackTrace(); }
	
	}else
	{
		byte[] data = ckey;
		for (byte theByte : data)
		{
  			System.out.println(Integer.toHexString(theByte));
		}

		
		SecretKey key2 = new SecretKeySpec(data, 0, data.length, "DES");
		
		return key2;
	
	}
	return null;
}
	
public static byte[] encrypt(byte[] input,boolean newkey) 
{
 	System.out.println("Inside encrypt()"); 
	try 
	{

		SecretKey key=getSecretKey(newkey); 

		Cipher desCipher=Cipher.getInstance("DES/ECB/PKCS5Padding");

		desCipher.init(Cipher.ENCRYPT_MODE,key);	
	
		byte[] textEncrypted = desCipher.doFinal(input); 

		System.out.println("Cipher Text  :" 
		+ new String(textEncrypted));
		
		return textEncrypted;

	}catch(NoSuchAlgorithmException e)
	{ e.printStackTrace(); }
	catch(NoSuchPaddingException e)
	{ e.printStackTrace(); }
	catch(InvalidKeyException e)
	{ e.printStackTrace(); }
	catch(IllegalBlockSizeException e)
	{ e.printStackTrace(); }
	catch(BadPaddingException e)
	{ e.printStackTrace(); } 
	
	return null;
}

public static String decrypt(byte[] encryptionBytes) 
//throws NoSuchAlgorithmException,InvalidKeyException, BadPaddingException, IllegalBlockSizeException 
{ 
	try {
	System.out.println("Inside decrypt()"); 
	Cipher desCipher=Cipher.getInstance("DES/ECB/PKCS5Padding");
	SecretKey key=getSecretKey(false);
	desCipher.init(Cipher.DECRYPT_MODE, key); 
	byte[] recoveredBytes = desCipher.doFinal(encryptionBytes); 
	String recovered = new String(recoveredBytes);
 	System.out.println("recovered Text  :" + recovered);
		
	System.out.println("Exiting decrypt()"); 
	return recovered;
	}
	catch(NoSuchAlgorithmException e)
	{ e.printStackTrace(); }
	catch(NoSuchPaddingException e)
	{ e.printStackTrace(); }
	catch(InvalidKeyException e)
	{ e.printStackTrace(); }
	catch(IllegalBlockSizeException e)
	{ e.printStackTrace(); }
	catch(BadPaddingException e)
	{ e.printStackTrace(); } 
	return null;	 
} 


/*    
    public static void main(String[] args) 
    {
    	
    	CipherDES des=new CipherDES();

   	String message="alogane-adoro";
    	byte[] encryptionBytes=des.encrypt(message.getBytes(),true);
	decrypt(encryptionBytes);
    }*/    
}
