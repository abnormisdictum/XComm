package org.structure;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.apache.commons.codec.binary.Base64;

public class Auth 
{
	private static String ALGO = "SHA256withRSA";
	private static String CHARSET = "UTF-16";
	
	public static String sign(String data, PrivateKey localPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException
	{
		Signature sig = Signature.getInstance(ALGO);
		sig.initSign(localPrivateKey);
		sig.update(data.getBytes(CHARSET));
		return Base64.encodeBase64String(sig.sign());
	}
	
	public static boolean verify(String message, String signature, PublicKey remotePublicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException
	{
		Signature sig = Signature.getInstance(ALGO);
		sig.initVerify(remotePublicKey);
		sig.update(message.getBytes(CHARSET));
		return sig.verify(Base64.decodeBase64(signature));
	}
}
