package com.gpg.demogpg.controller;

import java.util.Base64;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.gpg.demogpg.service.PGPKeyService;
import com.gpg.demogpg.service.PGPService;

@RestController
public class EncryptioController {

	private final PGPService service;
	private final PGPPublicKey publicKey;
	private final PGPPrivateKey privateKey;

	public EncryptioController(
			PGPService service,
			PGPKeyService keyService,
			@Value("${pgp.passphrase}") String passphrase,
			@Value("${pgp.path.private-key}") String filePathPrivateKey,
			@Value("${pgp.path.public-key}") String filePathPublicKey
	) throws Exception {
		this.service = service;
		this.publicKey = keyService.loadPublicKey(filePathPublicKey);
		this.privateKey = keyService.loadPrivateKey(filePathPrivateKey, passphrase.toCharArray());
	}

	@PostMapping("/encrypt")
	public String encrypt(@RequestBody String data) throws Exception {
		return Base64.getEncoder().encodeToString(service.encrypt(data.getBytes(), publicKey));
	}

	@PostMapping("/decrypt")
	public String decrypt(@RequestBody String base64Data) throws Exception {
		byte[] encryptData = Base64.getDecoder().decode(base64Data);
		byte[] decryptedData = service.decrypt(encryptData, privateKey);
		return new String(decryptedData);
	}
}
