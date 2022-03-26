package io.forest;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hello world!
 *
 */
public class App {
	static {
		Security.setProperty("crypto.policy", "unlimited");
	}
	private static final String algorithm = "PBKDF2WithHmacSHA256";

	public static void main(String[] args) throws Exception {
		String password = "password";
		SecureRandom secureRandom = new SecureRandom();
		byte[] salt = new byte[512];
		secureRandom.nextBytes(salt);
		
		SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
		
		// Password Based Encryption (PBE) specification
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
		
		SecretKey tmp = factory.generateSecret(spec);
		System.out.println("Algorithm: " + tmp.getAlgorithm());
		System.out.println(Base64.getEncoder().encodeToString(tmp.getEncoded()));
		
		// Convert PBE to AES key
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		System.out.println("Algorithm: " + secret.getAlgorithm());
		System.out.println(Base64.getEncoder().encodeToString(secret.getEncoded()));
		
		
		
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");//"AES/CBC/PKCS5Padding");
		
		System.out.println(String.format("Block size: %d byte ", cipher.getBlockSize()));
		AlgorithmParameters params = cipher.getParameters();
		byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		
		System.out.println(String.format("Len: %d byte\nVal: %s", iv.length, Base64.getEncoder().encodeToString(iv)));
		cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
		
		byte[] ciphertext = cipher.doFinal("Hello, World!".getBytes(StandardCharsets.UTF_8));
		
		//Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
		String plaintext = new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
		System.out.println(plaintext);
	}
}
