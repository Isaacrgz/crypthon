package com.iri.crypthon;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

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

		System.out.println(inputFile.getParent());
		System.out.println(inputFile.getName());
		String name = inputFile.getName();
		
		String fileName = name.substring(0, name.indexOf("."));
		System.out.println(fileName);

		File encryptedFile = new File(inputFile.getParent(), fileName.concat(".encrypted"));
		Crypton.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
	}

	public static void dencryptProcess(String password, String salt, String path)
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

		System.out.println(inputFile.getParent());
		System.out.println(inputFile.getName());
		String name = inputFile.getName();
		
		String fileName = name.substring(0, name.indexOf("."));
		System.out.println(fileName);

//		File encryptedFile = new File(inputFile.getParent(), name);
		File decryptedFile = new File(inputFile.getParent(), fileName.concat(".decrypted"));
		Crypton.decryptFile(algorithm, key, ivParameterSpec, inputFile, decryptedFile);
	}

}
