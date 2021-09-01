package io.forest;

public interface ICipherAlgo {

	byte[] encrypt(byte[] payload, ICryptoSpec cryptoSpec) throws Exception;

	byte[] decrypt(byte[] encryptedPayload, ICryptoSpec cryptoSpec) throws Exception;
}
