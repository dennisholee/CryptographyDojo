package io.forest;

import javax.crypto.spec.SecretKeySpec;

public interface ICryptoSpec {

	String algorithm();

	String cipherTransformer();

	SecretKeySpec keySpec();

	byte[] IV();

}
