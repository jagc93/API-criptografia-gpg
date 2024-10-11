package com.gpg.demogpg.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.springframework.stereotype.Service;

@Service
public class PGPService {

	public byte[] encrypt(byte[] data, PGPPublicKey publicKey) throws PGPException, IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
			new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
				.setWithIntegrityPacket(true)
				.setSecureRandom(new SecureRandom())
				.setProvider("BC")
		);

		encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey));
		OutputStream encryptedOut = encryptedDataGenerator.open(byteArrayOutputStream, data.length);
		encryptedOut.write(data);
		encryptedOut.close();

		return byteArrayOutputStream.toByteArray();
	}

	public byte[] decrypt(byte[] encryptedData, PGPPrivateKey privateKey) throws PGPException, IOException {
		InputStream in = new ByteArrayInputStream(encryptedData);
		PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
		PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
		PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.get(0);
		InputStream clear = publicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));		
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		int ch;

		while ((ch = clear.read()) > 0) {
			byteArrayOutputStream.write(ch);
		}

		return byteArrayOutputStream.toByteArray();
	}
}
