package io.forest;

import static org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.stream.StreamSupport;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.encoders.Hex;

/**
 * Hello world!
 *
 */
public class App {
	public static void main(String[] args) throws Exception {
		int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
		System.out.println("Max Key Size for AES : " + maxKeySize);

		RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();
		SecureRandom random = SecureRandom.getInstanceStrong();
		int keySize = 2048;
		KeyGenerationParameters param = new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, keySize,
				12);
		rsaKeyPairGenerator.init(param);

		int algorithm = PGPPublicKey.RSA_ENCRYPT;
		Date date = new Date();

		BcPGPKeyPair bcPGPKeyPair = new BcPGPKeyPair(algorithm, rsaKeyPairGenerator.generateKeyPair(), date);

		byte[] encrypt = encrypt("Hello world".getBytes(), bcPGPKeyPair.getPublicKey(), null, false, false, new Date(),
				AES_256);
		System.out.println(String.format("Encrypted> %s", Base64.getEncoder().encodeToString(encrypt)));

		listKeys("/Users/dennislee/Devs/CryptographyDojo/04_PGP/pubkey.asc");
	}

//	@SuppressWarnings({ "rawtypes", "deprecation" })
//	public static byte[] decrypt(byte[] encrypted, InputStream keyIn, char[] password) throws Exception {
//		InputStream inb = new ByteArrayInputStream(encrypted);
//		InputStream in = PGPUtil.getDecoderStream(inb);
//
//		try {
//			PGPObjectFactory pgpF = new PGPObjectFactory(in);
//			PGPEncryptedDataList enc = null;
//			Object o = pgpF.nextObject();
//			if (o == null)
//				throw new Exception("@550 No data in message");
//
//			if (o instanceof PGPEncryptedDataList)
//				enc = (PGPEncryptedDataList) o;
//			else
//				enc = (PGPEncryptedDataList) pgpF.nextObject();
//
//			// deadcode: if (o==null) throw new Exception("@550 No dataList in message");
//
//			Iterator it = enc.getEncryptedDataObjects();
//			PGPPrivateKey sKey = null;
//			PGPPublicKeyEncryptedData pbe = null;
//			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
//
//			while (sKey == null && it.hasNext()) {
//				pbe = (PGPPublicKeyEncryptedData) it.next();
//				sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
//			}
//
//			if (sKey == null)
//				throw new IllegalArgumentException("@550 SecretKey not found");
//			InputStream clear = pbe.getDataStream(sKey, "BC");
//			PGPObjectFactory pgpFact = new PGPObjectFactory(clear);
//			PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();
//			pgpFact = new PGPObjectFactory(cData.getDataStream());
//			PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
//			InputStream unc = ld.getInputStream();
//			ByteArrayOutputStream out = new ByteArrayOutputStream();
//
//			int ch;
//			while ((ch = unc.read()) >= 0) {
//				out.write(ch);
//			}
//
//			byte[] rs = out.toByteArray();
//			try {
//				in.close();
//			} catch (Exception I) {
//			}
//			try {
//				inb.close();
//			} catch (Exception I) {
//			}
//			out.close();
//			return rs;
//
//		} catch (Exception E) {
//			try {
//				in.close();
//			} catch (Exception I) {
//			}
//			try {
//				inb.close();
//			} catch (Exception I) {
//			}
//			throw E;
//		}
//	}

	public static void listKeys(String filePath) throws FileNotFoundException, IOException, PGPException {

		Map<String, Object> keys = new WeakHashMap<>();

		try (FileInputStream fileInputStream = new FileInputStream(filePath);
				InputStream in = PGPUtil.getDecoderStream(fileInputStream)) {

			KeyFingerPrintCalculator fingerprintCalculator = new BcKeyFingerprintCalculator();
			PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, fingerprintCalculator);

			pgpPub.iterator().forEachRemaining(k -> {

				String keyHex = Hex.toHexString(k.getPublicKey().getFingerprint());
				System.out.println(String.format("fingerprint: %s", keyHex));
				Iterator<PGPPublicKey> i = k.getPublicKeys();
				
				while (i.hasNext()) {
					PGPPublicKey key = i.next();
					key.getUserAttributes().forEachRemaining(System.out::println);
				}

				Map<String, Object> keyData = new WeakHashMap<>();
				keys.put(keyHex, keyData);

				
			});
		}

	}

	public static void getPublicKey(String filePath)
			throws PGPException, NoSuchProviderException, FileNotFoundException, IOException {

		FileInputStream fileInputStream = new FileInputStream(filePath);

		InputStream in = PGPUtil.getDecoderStream(fileInputStream);

		KeyFingerPrintCalculator fingerprintCalculator = new BcKeyFingerprintCalculator();
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, fingerprintCalculator);

		//
		// we just loop through the collection till we find a key suitable for
		// encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//

		//
		// iterate through the key rings.
		//

		pgpPub.iterator().forEachRemaining(k -> {
			System.out.println(Hex.toHexString(k.getPublicKey().getFingerprint()));
		});
		Iterator<?> rIt = pgpPub.getKeyRings();

		while (rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator<?> kIt = kRing.getPublicKeys();

			while (kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();

				// System.out.println(Hex.toHexString(k.getFingerprint()));
				// System.out.println(Base64.getEncoder().encodeToString(k.getFingerprint()));

//				if (k.isEncryptionKey()) {
//					return new BcPGPKeyConverter().getPGPPublicKey(algorithm, algorithmParameters, pubKey, time)getPublicKey(k);
			}
		}
	}

	public static byte[] encrypt(byte[] clearData, PGPPublicKey encKey, String fileName, boolean withIntegrityCheck,
			boolean armor, Date At, int PGPEncryptedDataAlgo) throws Exception {
		if (fileName == null)
			fileName = PGPLiteralData.CONSOLE;

		// Empty byte array output stream.
		ByteArrayOutputStream ous = new ByteArrayOutputStream();

		// Input data to stream.
		PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
		OutputStream datastream = pgpLiteralDataGenerator.open(ous, PGPLiteralDataGenerator.UTF8, fileName,
				clearData.length, new Date());
		datastream.write(clearData);

		// Compress output stream using ZIP
		PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(
				PGPCompressedDataGenerator.ZIP);
		OutputStream zipStream = pgpCompressedDataGenerator.open(datastream);
//		zipStream.write(clearData);

		// Encrypt Stream using public key
		PGPDataEncryptorBuilder encryptorBuilder = new BcPGPDataEncryptorBuilder(AES_256);
		PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);

		PGPKeyEncryptionMethodGenerator method = new BcPublicKeyKeyEncryptionMethodGenerator(encKey);
		pgpEncryptedDataGenerator.addMethod(method);

		ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream();

		byte[] bytes = ous.toByteArray();
		OutputStream cOut = pgpEncryptedDataGenerator.open(encryptedStream, bytes.length);
		cOut.write(bytes);
		cOut.close();
		encryptedStream.close();

		byte[] ciphered = encryptedStream.toByteArray();

		return ciphered;
	}

//	public static void f() {
//		final PGPLiteralData msg = asLiteral(encryptedMessage, secretKeyRing, secretPwd);
//		final ByteArrayOutputStream out = new ByteArrayOutputStream();
//		Streams.pipeAll(msg.getInputStream(), out);
//		return out.toByteArray();
//	}
//
//	private static PGPLiteralData asLiteral(PGPPrivateKey privateKey, final byte[] message, final InputStream secretKeyRing,
//			final String secretPwd) throws IOException, PGPException {
//		//PGPPrivateKey key = null;
//		PGPPublicKeyEncryptedData encrypted = null;
//		final PGPSecretKeyRingCollection keys = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretKeyRing),
//				new JcaKeyFingerprintCalculator());
//		for (final Iterator<PGPPublicKeyEncryptedData> i = getEncryptedObjects(message); (key == null)
//				&& i.hasNext();) {
//			encrypted = i.next();
//			key = getPrivateKey(keys, encrypted.getKeyID(), secretPwd);
//		}
//		if (key == null) {
//			throw new IllegalArgumentException("secret key for message not found.");
//		}
//		final InputStream stream = encrypted
//				.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(provider).build(key));
//		return asLiteral(stream);
//	}
}
