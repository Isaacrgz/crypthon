package com.iri.crypthon;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Process {

	private Process() {
	}

	public static void encryptProcess(String password, String salt, String path)
			throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException,
			BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeySpecException {
		SecretKey key;
		try {
			key = Crypton.getKeyFromPassword(password, salt);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return;
		}
		String algorithm = "AES/CBC/PKCS5Padding";
		IvParameterSpec ivParameterSpec = Crypton.generateIv();
		File inputFile = new File(path);
		String name = inputFile.getName();
		String fileName = name.substring(0, name.indexOf("."));
		File encryptedFile = new File(inputFile.getParent(), fileName.concat(".encrypted"));
		Crypton.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
		System.out.println("Encrypt finished");
	}

	public static void encryptProcess(String password, String path) throws IOException {
		byte[] encrypted = Crypton.encryptAES256(FileManager.read(Path.of(path)), password);
		System.out.println(Base64.getEncoder().encodeToString(encrypted));

		System.out.println("Encrypt finished");
	}

	public static void decryptProcess(String password, String salt, String path)
			throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException,
			BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeySpecException {
		SecretKey key;
		try {
			key = Crypton.getKeyFromPassword(password, salt);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return;
		}
		String algorithm = "AES/CBC/PKCS5Padding";
		IvParameterSpec ivParameterSpec = Crypton.generateIv();
		File inputFile = new File(path);
		String name = inputFile.getName();
		String fileName = name.substring(0, name.indexOf("."));
		File decryptedFile = new File(inputFile.getParent(), fileName.concat(".decrypted"));
		Crypton.decryptFile(algorithm, key, ivParameterSpec, inputFile, decryptedFile);

		System.out.println("Decrypt finished");
	}

	public static void decryptProcess(String password, String path) throws IOException {
		byte[] decrypted = Crypton.decryptAES256(FileManager.read(Path.of(path)), password);
		System.out.println(new String(decrypted, StandardCharsets.UTF_8));

		System.out.println("Decrypt finished");
	}

}
