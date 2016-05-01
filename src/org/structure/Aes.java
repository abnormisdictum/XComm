package org.structure;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Aes 
{
	private static String TRANSFORM = "AES/CBC/PKCS5Padding";
	private static int KEY_SIZE = 128;
	private static String CHARSET = "UTF-16";
	
	public static String encrypt(String data, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	{
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.ENCRYPT_MODE, secretKey);
		return Base64.encodeBase64String(c.doFinal(data.getBytes(CHARSET)))+"<IV>"+Base64.encodeBase64String(c.getIV());
	}
	
	public static String decrypt(String enc, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException
	{
		String[] data_a = enc.split("<IV>");
		byte[] iv = Base64.decodeBase64(data_a[1]);
		byte[] data = Base64.decodeBase64(data_a[0]);
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		return new String(c.doFinal(data), CHARSET);
	}
	
	public static SecretKey generateSecretKey() throws NoSuchAlgorithmException
	{
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(KEY_SIZE);
		return kg.generateKey();
	}
	
	public static SecretKey getMessageSecretKey(SecretKey masterSecretKey, MovingFactor mf, long msg_no) throws NoSuchAlgorithmException, InvalidKeyException
	{
		ByteBuffer bf = ByteBuffer.allocate(Long.BYTES);
		bf.putLong(mf.getMovingFactor(msg_no));
		Mac m = Mac.getInstance("HmacSHA256");
		m.init(masterSecretKey);
		m.update(bf.array());
		return (SecretKey) new SecretKeySpec(Arrays.copyOf(m.doFinal(), 16), "AES");
	}
}
