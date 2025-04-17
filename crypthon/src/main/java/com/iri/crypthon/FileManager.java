package com.iri.crypthon;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileManager {

	private FileManager() {
	}

	public static byte[] read(Path path) throws IOException {
		return Files.readAllBytes(path);
	}

}
