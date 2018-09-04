package com.pk.ei;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class RSAKeyDemo {
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair kp = keyGen.generateKeyPair();
		Key pub = kp.getPublic();
		Key pvt = kp.getPrivate();

		System.out.println("Private key format: " + pvt.getFormat());
		// prints "Private key format: PKCS#8" on my machine
		 
		System.err.println("Public key format: " + pub.getFormat());
		// prints "Public key format: X.509" on my machine

		System.out.println("Writing private key ...");
		String outFile = "/RSADemo2";
		FileOutputStream out = null;

		try{
			
			out = new FileOutputStream(outFile + ".key");
			out.write(pvt.getEncoded());

		}finally{
			if(out!=null)
				out.close();
		}
		
		System.out.println("Writing public key ...");		
		try{
			out = new FileOutputStream(outFile + ".pub");;
			out.write(pub.getEncoded());
		}finally{
			if(out!=null)
				out.close();
		}
	}

}
