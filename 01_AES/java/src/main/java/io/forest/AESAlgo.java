package io.forest;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESAlgo implements ICipherAlgo {

	public byte[] encrypt(byte[] payload, ICryptoSpec cryptoSpec) throws Exception {
		Cipher cipher = createCipher(cryptoSpec, Cipher.ENCRYPT_MODE);
		return cipher.doFinal(payload);
	}

	public byte[] decrypt(byte[] encryptedPayload, ICryptoSpec cryptoSpec) throws Exception {
		Cipher cipher = createCipher(cryptoSpec, Cipher.DECRYPT_MODE);
		return cipher.doFinal(encryptedPayload);
	}

	private Cipher createCipher(ICryptoSpec cryptoSpec, int mode) throws Exception {
		Cipher cipher = Cipher.getInstance(cryptoSpec.cipherTransformer());

		if (((AESAlgoSpec) cryptoSpec).AAD()) {
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AESAlgoDefaults.GCM_TAG_LENGTH.value(), cryptoSpec.IV());
			cipher.init(mode, cryptoSpec.keySpec(), gcmParameterSpec);
		} else {
			cipher.init(mode, cryptoSpec.keySpec());
		}

		return cipher;

	}

	public static class AESAlgoSpecBuilder implements ICryptoSpecBuilder {

		private static String ALGORITHM = "AES";

		private int keySize = AESAlgoDefaults.AES_KEY_SIZE.value();
		private int ivLength = AESAlgoDefaults.GCM_IV_LENGTH.value();
		private boolean isAAD = false;

		public AESAlgoSpecBuilder keySize(final int keySize) {
			this.keySize = keySize;
			return this;
		}

		public AESAlgoSpecBuilder AAD(final boolean isAAD) {
			this.isAAD = isAAD;
			return this;
		}
		
		public AESAlgoSpecBuilder keystore(String path) {
			// TODO: Retrieve file from keystore.
			return this;
		}

		@Override
		public ICryptoSpec build() throws NoSuchAlgorithmException {

			byte[] IV = new byte[this.ivLength];
			SecureRandom random = new SecureRandom();
			random.nextBytes(IV);

			KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
			keyGenerator.init(this.keySize);

			SecretKey key = keyGenerator.generateKey();

			return new AESAlgoSpec(ALGORITHM, key.getEncoded(), IV, this.isAAD);
		}

	}

	public static class AESAlgoSpec implements ICryptoSpec {

		private String algorithm;

		private byte[] key;

		private byte[] IV;

		private boolean AAD;

		public AESAlgoSpec(String algorithm, byte[] key, byte[] IV, boolean AAD) {
			this.algorithm = algorithm;
			this.key = key;
			this.IV = IV;
			this.AAD = AAD;
		}

		@Override
		public String cipherTransformer() {
			return "AES/GCM/NoPadding";
		}

		@Override
		public String algorithm() {
			return this.algorithm;
		}

		@Override
		public byte[] IV() {
			return this.IV;
		}

		public boolean AAD() {
			return this.AAD;
		}

		public SecretKeySpec keySpec() {
			return new SecretKeySpec(this.key, this.algorithm);
		}
	}

	public static enum AESAlgoDefaults {

		AES_KEY_SIZE(256), GCM_IV_LENGTH(12), GCM_TAG_LENGTH(128);

		private int value;

		private AESAlgoDefaults(int value) {
			this.value = value;
		}

		public int value() {
			return this.value;
		}
	}
}
