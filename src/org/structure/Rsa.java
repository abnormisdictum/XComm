package org.structure;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;

public class Rsa 
{
	private static String TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	private static int KEY_SIZE = 1024;
	
	public static String wrapKey(SecretKey secretkey, PublicKey remotePublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException
	{
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.WRAP_MODE, remotePublicKey);
		return Base64.encodeBase64String(c.wrap(secretkey));
	}
	
	public static SecretKey unwrapKey(String data, PrivateKey localPrivateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException
	{
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.UNWRAP_MODE, localPrivateKey);
		return (SecretKey) c.unwrap(Base64.decodeBase64(data), "AES", Cipher.SECRET_KEY);
	}
	
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(KEY_SIZE, new SecureRandom());
		return kpg.generateKeyPair();
	}
	
	public static String translate(PublicKey publicKey)
	{
		X509EncodedKeySpec x = new X509EncodedKeySpec(publicKey.getEncoded());
		return Base64.encodeBase64String(x.getEncoded());
	}
	
	public static PublicKey translate(String data) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		KeyFactory kf = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x = new X509EncodedKeySpec(Base64.decodeBase64(data));
		return (PublicKey) kf.generatePublic(x);
	}
}
