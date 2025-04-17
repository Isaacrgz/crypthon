package com.iri.crypthon;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypton {

	// The number of times that the password is hashed during the derivation of the
	// symmetric key
	private static final int PBKDF2_ITERATION_COUNT = 300_000;
	private static final int PBKDF2_SALT_LENGTH = 16; // 128 bits
	private static final int AES_KEY_LENGTH = 256; // in bits
	// An initialization vector size
	private static final int GCM_NONCE_LENGTH = 12; // 96 bits
	// An authentication tag size
	private static final int GCM_TAG_LENGTH = 128; // in bits

	private Crypton() {
	}

	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(n);
		return keyGenerator.generateKey();
	}

	public static SecretKey getKeyFromPassword(String password, String salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
	}

	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] cipherText = cipher.doFinal(input.getBytes());
		return Base64.getEncoder().encodeToString(cipherText);
	}

	public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		return new String(plainText);
	}

	public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File inputFile, File outputFile)
			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		FileInputStream inputStream = new FileInputStream(inputFile);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();
	}

	public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File encryptedFile,
			File decryptedFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		FileInputStream inputStream = new FileInputStream(encryptedFile);
		FileOutputStream outputStream = new FileOutputStream(decryptedFile);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] output = cipher.doFinal();
		if (output != null) {
			outputStream.write(output);
		}
		inputStream.close();
		outputStream.close();
	}

	public static byte[] encryptAES256(byte[] input, String password) {
		try {
			SecureRandom secureRandom = SecureRandom.getInstanceStrong();
			// Derive the key, given password and salt
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			// A salt is a unique, randomly generated string
			// that is added to each password as part of the hashing process
			byte[] salt = new byte[PBKDF2_SALT_LENGTH];
			secureRandom.nextBytes(salt);
			PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATION_COUNT, AES_KEY_LENGTH);
			byte[] secret = factory.generateSecret(keySpec).getEncoded();
			SecretKey key = new SecretKeySpec(secret, "AES");

			// AES-GCM encryption
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			// A nonce or an initialization vector is a random value chosen at encryption
			// time
			// and meant to be used only once
			byte[] nonce = new byte[GCM_NONCE_LENGTH];
			secureRandom.nextBytes(nonce);
			// An authentication tag
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
			byte[] encrypted = cipher.doFinal(input);
			// Salt and nonce can be stored together with the encrypted data
			// Both salt and nonce have fixed length, so can be prefixed to the encrypted
			// data
			ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + nonce.length + encrypted.length);
			byteBuffer.put(salt);
			byteBuffer.put(nonce);
			byteBuffer.put(encrypted);
			return byteBuffer.array();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static byte[] decryptAES256(byte[] encrypted, String password) {
		try {
			// Salt and nonce have to be extracted
			ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);
			byte[] salt = new byte[PBKDF2_SALT_LENGTH];
			byteBuffer.get(salt);
			byte[] nonce = new byte[GCM_NONCE_LENGTH];
			byteBuffer.get(nonce);
			byte[] cipherBytes = new byte[byteBuffer.remaining()];
			byteBuffer.get(cipherBytes);

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATION_COUNT, AES_KEY_LENGTH);
			byte[] secret = factory.generateSecret(keySpec).getEncoded();
			SecretKey key = new SecretKeySpec(secret, "AES");

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			// If encrypted data is altered, during decryption authentication tag
			// verification will fail
			// resulting in AEADBadTagException
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
			cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
			return cipher.doFinal(cipherBytes);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}