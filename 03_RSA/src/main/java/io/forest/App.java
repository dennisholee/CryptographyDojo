package io.forest;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Hello world!
 *
 */
public class App {
	public static void main(String[] args) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding"); //"RSA/ECB/PKCS1Padding");
//		OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"),
//				PSource.PSpecified.DEFAULT);
		KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
		pairGenerator.initialize(2048, SecureRandom.getInstanceStrong());
		KeyPair keyPair = pairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		cipher.init(Cipher.ENCRYPT_MODE, privateKey);//, oaepParams);
		byte[] encryptedData = cipher.doFinal("Hello".getBytes());
		
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		
		byte[] decryptedData = cipher.doFinal(encryptedData);
		System.out.println(new String(decryptedData));
		
	}
}
