package org.structure;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Message 
{
	private String message;
	private long msg_no;
	private String signature;
	
	public Message(String message, long msg_no, SecretKey masterSecretKey, PrivateKey localPrivateKey, MovingFactor mf) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, SignatureException
	{
		this.message = Aes.encrypt(message, Aes.getMessageSecretKey(masterSecretKey, mf, msg_no));
		this.signature = Auth.sign(this.message, localPrivateKey);
		this.msg_no = msg_no;
	}
	
	public String getMessage(SecretKey masterSecretKey, MovingFactor mf, PublicKey remotePublicKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		if(!Auth.verify(this.message, this.signature, remotePublicKey))
			destroy();
		
		return Aes.decrypt(this.message, Aes.getMessageSecretKey(masterSecretKey, mf, this.msg_no));
	}
	
	public void destroy()
	{
		this.message = "Nullified";
		this.signature = "Nullified";
		this.msg_no = 0;
	}
}
