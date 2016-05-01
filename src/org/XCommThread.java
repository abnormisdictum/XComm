package org;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.math3.random.RandomDataGenerator;
import org.structure.Aes;
import org.structure.Message;
import org.structure.MovingFactor;
import org.structure.Rsa;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public class XCommThread extends Thread
{
	private SecretKey outerLayerSecretKey;
	private SecretKey masterSecretKey;
	private PrivateKey localPrivateKey;
	private PublicKey localPublicKey;
	private PublicKey remotePublicKey;
	private MovingFactor mf;
	private boolean isClient, isClientControlled;
	private long msg_no, msg_no_inc;
	private Socket socket;
	private PrintWriter out;
	private BufferedReader in;
	private Gson g = new Gson();
	private boolean connection_established = false;
	
	private ConcurrentLinkedQueue<String> inQueue;
	private ConcurrentLinkedQueue<String> outQueue;
	
	public XCommThread(Socket s, ConcurrentLinkedQueue<String> inQueue, ConcurrentLinkedQueue<String> outQueue, boolean isClient, boolean isClientControlled, PrivateKey localPrivateKey, PublicKey localPublicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, JsonSyntaxException, InvalidAlgorithmParameterException
	{
		this.socket = s;
		this.inQueue = inQueue;
		this.outQueue = outQueue;
		this.isClient = isClient;
		this.isClientControlled = isClientControlled;
		RandomDataGenerator rdg = new RandomDataGenerator();
		this.msg_no = rdg.nextSecureLong(-100, 100);
		this.msg_no_inc = rdg.nextSecureLong(-10, 10);
		
		out = new PrintWriter(this.socket.getOutputStream(), true);
		in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
		
		if(localPublicKey == null || localPrivateKey == null)
		{
			KeyPair kp = Rsa.generateKeyPair();
			this.localPrivateKey = kp.getPrivate();
			this.localPublicKey = kp.getPublic();
		}
		else
		{
			this.localPrivateKey = localPrivateKey;
			this.localPublicKey = localPublicKey;
		}
		
		this.out.println(Rsa.translate(this.localPublicKey));
		this.remotePublicKey = Rsa.translate(this.in.readLine());
		
		if(this.isClient)
			initAsClient();
		if(!this.isClient)
			initAsServer();
		
		System.out.println("Connection estsblished");
		this.start();
	}
	
	private void initAsClient() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, JsonSyntaxException, InvalidAlgorithmParameterException
	{
		if(this.isClientControlled)
		{
			this.outerLayerSecretKey = Aes.generateSecretKey();
			this.masterSecretKey = Aes.generateSecretKey();
			this.mf = new MovingFactor();
			this.out.println(Rsa.wrapKey(outerLayerSecretKey, this.remotePublicKey));
			this.out.println(Rsa.wrapKey(masterSecretKey, this.remotePublicKey));
			this.out.println(Aes.encrypt(g.toJson(mf), this.outerLayerSecretKey));
			this.connection_established = true;
		}
		
		if(!this.isClientControlled)
		{
			this.outerLayerSecretKey = Rsa.unwrapKey(this.in.readLine(), localPrivateKey);
			this.masterSecretKey = Rsa.unwrapKey(this.in.readLine(), localPrivateKey);
			this.mf = g.fromJson(Aes.decrypt(this.in.readLine(), this.outerLayerSecretKey), MovingFactor.class);
			this.connection_established = true;
		}
	}
	
	private void initAsServer() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, JsonSyntaxException, InvalidAlgorithmParameterException
	{
		if(!this.isClientControlled)
		{
			this.outerLayerSecretKey = Aes.generateSecretKey();
			this.masterSecretKey = Aes.generateSecretKey();
			this.mf = new MovingFactor();
			this.out.println(Rsa.wrapKey(outerLayerSecretKey, this.remotePublicKey));
			this.out.println(Rsa.wrapKey(masterSecretKey, this.remotePublicKey));
			this.out.println(Aes.encrypt(g.toJson(mf), this.outerLayerSecretKey));
			this.connection_established = true;
		}
		
		if(this.isClientControlled)
		{
			this.outerLayerSecretKey = Rsa.unwrapKey(this.in.readLine(), localPrivateKey);
			this.masterSecretKey = Rsa.unwrapKey(this.in.readLine(), localPrivateKey);
			this.mf = g.fromJson(Aes.decrypt(this.in.readLine(), this.outerLayerSecretKey), MovingFactor.class);
			this.connection_established = true;
		}
	}
	
	public void sendMessage(String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, SignatureException
	{
		Message m = new Message(message, this.msg_no, this.masterSecretKey, this.localPrivateKey, this.mf);
		out.println(Aes.encrypt(this.g.toJson(m), this.outerLayerSecretKey));
		this.msg_no+=this.msg_no_inc;
	}
	
	public String readMessage() throws JsonSyntaxException, IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		String x, ret = new String();
		if((x = this.in.readLine())!=null)
		{
			Message m = this.g.fromJson(Aes.decrypt(x, this.outerLayerSecretKey), Message.class);
			ret = m.getMessage(this.masterSecretKey, this.mf, this.remotePublicKey);
		}
		else ret =null;
		System.out.println(ret);
		return ret;
	}
	
	public void close() throws IOException, InterruptedException
	{
		this.masterSecretKey = null;
		this.outerLayerSecretKey = null;
		this.socket.close();
		this.out.close();
		this.in.close();
		this.mf = null;
		this.localPrivateKey = null;
		this.localPublicKey = null;
		this.g = null;
		this.msg_no = 0;
		this.msg_no_inc = 0;
		this.remotePublicKey = null;
		this.connection_established = false;
		this.join();
	}
	
	public boolean hasConnected()
	{
		return this.connection_established;
	}
	
	public void run()
	{
		System.out.println("Thread Running");
		while(this.isAlive())
		{
			try
			{
				if(this.in.ready())
				{
					Message m = this.g.fromJson(Aes.decrypt(this.in.readLine(), this.outerLayerSecretKey), Message.class);
					this.inQueue.add(m.getMessage(this.masterSecretKey, this.mf, this.remotePublicKey));
				}
				
				if(this.outQueue.size()>0)
				{
					Message m = new Message(this.outQueue.poll(), this.msg_no, this.masterSecretKey, this.localPrivateKey, this.mf);
					out.println(Aes.encrypt(this.g.toJson(m), this.outerLayerSecretKey));
					this.msg_no+=this.msg_no_inc;
				}
			} 
			catch (JsonSyntaxException | InvalidKeyException | NoSuchAlgorithmException | SignatureException
					| NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException
					| BadPaddingException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
