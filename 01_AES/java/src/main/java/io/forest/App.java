package io.forest;

import java.util.Base64;

import io.forest.AESAlgo.AESAlgoSpecBuilder;

public class App
{
    static String plainText = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";
    
    public static void main(String args[]) throws Exception {
    	ICryptoSpec cryptoSpec = new AESAlgoSpecBuilder().AAD(true).build();
    	AESAlgo aesAlgo = new AESAlgo();
    	byte[] encryptedPayload = aesAlgo.encrypt(plainText.getBytes(), cryptoSpec);
    	byte[] decryptedPayload = aesAlgo.decrypt(encryptedPayload, cryptoSpec);
    	
    	
    	System.out.println("{\"SecretKey\" : \"" + Base64.getEncoder().encodeToString(cryptoSpec.keySpec().getEncoded()) + "\",");
    	System.out.println(" \"IV\"        : \"" + Base64.getEncoder().encodeToString(cryptoSpec.IV()) + "\",");
    	System.out.println(" \"Plain\"     : \"" + plainText  + "\",");
    	System.out.println(" \"Encrypted\" : \"" + Base64.getEncoder().encodeToString(encryptedPayload) + "\",");
    	System.out.println(" \"Decrypted\" : \"" + new String(decryptedPayload) + "\"}"); 	
    }
}