import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_Encryptor {
	public static String mode = "decrypt";

	public static String encrypt(byte[] encryptionKey, byte[] initVector, String plaintext) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec cKeySpec = new SecretKeySpec(encryptionKey, "AES");

			// Encrypt the thing
			Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, cKeySpec, iv);
			byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
			return Base64.getEncoder().encodeToString(encryptedBytes);

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

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

	public static String reader(String filename) {
		try {
			BufferedReader bufferedReader = new BufferedReader(new FileReader(filename));
			StringBuilder stringBuilder = new StringBuilder();
			String c = null;
			while ((c = bufferedReader.readLine()) != null) {
				stringBuilder.append(c).append("\n");
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

	public static void writeToFile(String out, String filename) {
		try {
			BufferedWriter outWriter = new BufferedWriter(new FileWriter(filename));
			outWriter.write(out);
			outWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static boolean verifyMAC(String MAC, String ciphertext, byte[] aKey) {
		Mac hmac;
		try {
			hmac = Mac.getInstance("HmacSHA256");
			hmac.init(new SecretKeySpec(aKey, "HmacSHA256"));
			return MAC.equals(Base64.getEncoder().encodeToString(hmac.doFinal(ciphertext.getBytes())));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		// Return false if there was a problem.
		return false;
	}

	public static byte[] getBadKey() {
		return new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	}

	public static void main(String[] args) {

		SecureRandom random = new SecureRandom();
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

		if (mode.equalsIgnoreCase("encrypt")) {
			String plaintext = "Hello World";
			// String plaintext = reader("King James Bible.txt");

			long encryptBegin = System.nanoTime();
			String ciphertext = encrypt(encryptionKey, iv, plaintext);
			long encryptEnd = System.nanoTime();
			System.out.println("Time to encrypt: " + (encryptEnd - encryptBegin));

			long macBegin = System.nanoTime();
			String mac = createMAC(ciphertext, authenticationKey);
			long macEnd = System.nanoTime();
			System.out.println("Time to generate MAC: " + (macEnd - macBegin));

			writeToFile(ciphertext, "ciphertext.txt");
			writeToFile(mac, "MAC.txt");
		} else {

			String mac = reader("MAC.txt");
			String ciphertext = reader("ciphertext.txt");

			if (verifyMAC(mac, ciphertext, authenticationKey)) {
				long decryptBegin = System.nanoTime();
				String decryptedCiphertext = decrypt(encryptionKey, iv, ciphertext);
				long decryptEnd = System.nanoTime();
				System.out.println("Time to decrypt: " + (decryptEnd - decryptBegin));
				writeToFile(decryptedCiphertext, "decrypted.txt");

			} else {
				System.out.println("Input was not authentic. Decryption was aborted.");
			}
		}
	}
}