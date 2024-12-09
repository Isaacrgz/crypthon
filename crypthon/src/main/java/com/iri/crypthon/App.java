package com.iri.crypthon;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Main class
 *
 */
public class App {
	public static void main(String[] args)
			throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchPaddingException, IOException, InvalidKeySpecException {
		System.out.println("Crypton Secure Util");
		try (Scanner scanner = new Scanner(System.in)) {
			System.out.println("Choose an option");
			System.out.println("(1) Encrypt file");
			System.out.println("(2) Decrypt file");
			String option = scanner.nextLine();

			System.out.println("Enter the password:");
			String password = scanner.nextLine();

			System.out.println("Enter the salt:");
			String salt = scanner.nextLine();

			System.out.println("Enter the file path:");
			String path = scanner.nextLine();

			if (option.equals("1")) {
				Process.encryptProcess(password, salt, path);
			} else if (option.equals("2")) {
				Process.dencryptProcess(password, salt, path);
			}
		}
	}

}
