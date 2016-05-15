import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import java.security.NoSuchAlgorithmException;
//import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author Robert Ferguson
 * @author Jasmine Pedersen
 * @author Heather Pedersen
 */
public class AES_Encryptor {

	public static int mode = 0;
	public static final int ENCRYPT_MODE = 0;
	// Decrypting is implicitly any other input

	public static void main(String[] args) {
		// SecureRandom random = new SecureRandom();
		// Generate random 128 bit (16 bytes) key
		byte encryptionKey[] = new byte[16];
		// random.nextBytes(encryptionKey);
		encryptionKey = getBadKey();

		// Generate random key for authentication
		byte authenticationKey[] = new byte[16];
		// random.nextBytes(authenticationKey);
		authenticationKey = getBadKey();

		// Generate random 128 bit (16 bytes) IV, AES is always 16 bytes
		byte iv[] = new byte[16];
		// random.nextBytes(iv);
		iv = getBadKey();

		if (mode == ENCRYPT_MODE) {
			// String plaintext = "Hello World";
			String plaintext = readFromFile("King James Bible.txt");

			long encryptBegin = System.nanoTime();
			String ciphertext = encrypt(encryptionKey, iv, plaintext);
			long encryptEnd = System.nanoTime();
			System.out.println("Time to encrypt: " + (encryptEnd - encryptBegin));

			long macBegin = System.nanoTime();
			String mac = createMAC(ciphertext, authenticationKey);
			long macEnd = System.nanoTime();
			System.out.println("Time to generate MAC: " + (macEnd - macBegin));

			writeToFile(ciphertext, "ciphertext");
			writeToFile(mac, "MAC");
		} else {
			String mac = readFromFile("MAC");
			String ciphertext = readFromFile("ciphertext");

			if (verifyMAC(mac, ciphertext, authenticationKey)) {
				long decryptBegin = System.nanoTime();
				String decryptedCiphertext = decrypt(encryptionKey, iv, ciphertext);
				long decryptEnd = System.nanoTime();
				System.out.println("Time to decrypt: " + (decryptEnd - decryptBegin));
				writeToFile(decryptedCiphertext, "decrypted");
			} else {
				System.out.println("Input was not authentic. Decryption was aborted.");
			}
		}
	}

	/**
	 * Returns an encrypted version of the plaintext String using AES and the
	 * passed key and IV.
	 */
	public static String encrypt(byte[] encryptionKey, byte[] initVector, String plaintext) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec cKeySpec = new SecretKeySpec(encryptionKey, "AES");

			// Encrypt the things
			Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, cKeySpec, iv);
			byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
			return Base64.getEncoder().encodeToString(encryptedBytes);

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	/**
	 * Given the correct cipher key and IV to match the encrypted text, this
	 * method will return the non-encrypted version of the ciphertext.
	 */
	public static String decrypt(byte[] cKey, byte[] initVector, String encryptedText) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec cKeySpec = new SecretKeySpec(cKey, "AES");

			Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, cKeySpec, iv);

			byte[] ciphertextInput = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
			return new String(ciphertextInput);

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	/**
	 * Creates a Message Authentication Code based on the passed ciphertext and
	 * the passed authentication key, which should be different than the secret
	 * key used to encrypt.
	 */
	public static String createMAC(String ciphertext, byte[] aKey) {
		// authenticate the thing
		Mac hmac;
		try {
			hmac = Mac.getInstance("HmacSHA256");
			hmac.init(new SecretKeySpec(aKey, "HmacSHA256"));
			return Base64.getEncoder().encodeToString(hmac.doFinal(ciphertext.getBytes()));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		// Return null if there was a problem.
		return null;
	}

	/**
	 * Verifies that a MAC belongs to the passed ciphertext and authentication
	 * key.
	 */
	public static boolean verifyMAC(String MAC, String ciphertext, byte[] aKey) {
		Mac hmac;
		try {
			long macBegin = System.nanoTime();
			hmac = Mac.getInstance("HmacSHA256");
			hmac.init(new SecretKeySpec(aKey, "HmacSHA256"));
			long macEnd = System.nanoTime();
			System.out.println("Authenticated in " + (macEnd - macBegin) + "ns");
			return MAC.equals(Base64.getEncoder().encodeToString(hmac.doFinal(ciphertext.getBytes())));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		// Return false if there was a problem.
		return false;
	}

	/**
	 * Generates a bad key to encrypt with. Good for testing though.
	 */
	public static byte[] getBadKey() {
		return new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	}

	/**
	 * Reads a file and returns a String of it's contents.
	 */
	public static String readFromFile(String filename) {
		try {
			BufferedReader bufferedReader = new BufferedReader(new FileReader(filename));
			StringBuilder stringBuilder = new StringBuilder();
			String input = null;
			while ((input = bufferedReader.readLine()) != null) {
				stringBuilder.append(input);
			}

			bufferedReader.close();
			return stringBuilder.toString();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Writes a String out to a file.
	 */
	public static void writeToFile(String out, String filename) {
		try {
			BufferedWriter outWriter = new BufferedWriter(new FileWriter(filename));
			outWriter.write(out);
			outWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}