package com.iri.crypthon;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
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
			System.out.println("(2) Decrypt file\r\n");
			String option = scanner.nextLine();

			System.out.println("Enter the password: \r\n");
			String password = scanner.nextLine();

//			System.out.println("Enter the salt: \r\n");
//			String salt = scanner.nextLine();

			System.out.println("Enter the file path: \r\n");
			String path = scanner.nextLine();

			if (option.equals("1")) {
//				Process.encryptProcess(password, salt, String.format("/home/isaac/Documentos/%s", path));
				Process.encryptProcess(password, String.format("/home/isaac/Documentos/%s", path));
			} else if (option.equals("2")) {
//				Process.decryptProcess(password, salt, String.format("/home/isaac/Documentos/%s", path));
				Process.decryptProcess(password, String.format("/home/isaac/Documentos/%s", path));
			}
		}

//		String password = "Q8yRrM^AvV5r8Yx+"; // Password still has to be strong enough
////		  String sample = "WKKqeMW2QkOQpxC3ZdKP0mQGItDYg4fSopOZepnBTLrLdGjo1/DCIQesxwVgOVKyPXxDmhNcardsLNHzpllIFgoiAK3LW1+Hyaq2kPjGP8pYe39dOx88jj2IgWDxw3Sf5d3yUy6Bo06QTswgWzVnva/XJiVv/WqOw71lEZdW5D6PKghEZgnw4gIWMeghjHBdew==";
//		String input = """
//				Correo
//				isaacrgz97@gmail.com		contra"5#1
//				zackfennty@yahoo.com		contra%2!
//
//				SAT
//				ROII970430					iri97ngm
//				 """;
//		byte[] encrypted = Crypton.encryptAES256(input.getBytes(StandardCharsets.UTF_8), password);
//		System.out.println(Base64.getEncoder().encodeToString(encrypted));
//		// s+AwwowLdSb3rFZ6jJlxSXBvzGz7uB6+g2e97QXGRKUY5sHPgf94AOoybkzuR3rNREMj56Ik1+Co682s4vT2sAQ/
//		byte[] decrypted = Crypton.decryptAES256(encrypted, password);
//		System.out.println(new String(decrypted, StandardCharsets.UTF_8));
		// Sample text to encrypt
	}

}
