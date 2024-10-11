package com.gpg.demogpg.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.springframework.stereotype.Service;

@Service
public class PGPKeyService {

	public PGPPublicKey loadPublicKey(String filePath) throws PGPException, IOException {
	    try (InputStream keyIn = new FileInputStream(filePath)) {
	        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
	            PGPUtil.getDecoderStream(keyIn),
	            new JcaKeyFingerprintCalculator()
	        );

	        for (PGPPublicKeyRing keyRing : pgpPub) {
	            for (PGPPublicKey key : keyRing) {
	                if (key.isEncryptionKey()) {
	                    return key;
	                }
	            }
	        }

	        throw new IllegalArgumentException("No encryption key found in the provided file.");
	    }
	}

	public PGPPrivateKey loadPrivateKey(String filePath, char[] passphrase) throws PGPException, IOException {
	    try (InputStream keyIn = new FileInputStream(filePath)) {
	        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
	            PGPUtil.getDecoderStream(keyIn),
	            new JcaKeyFingerprintCalculator()
	        );

	        for (PGPSecretKeyRing keyRing : pgpSec) {
	            PGPSecretKey secretKey = keyRing.getSecretKey();
	            if (secretKey != null) {
	                return secretKey.extractPrivateKey(
	                    new JcePBESecretKeyDecryptorBuilder()
	                        .setProvider("BC")
	                        .build(passphrase)
	                );
	            }
	        }

	        throw new IllegalArgumentException("No private key found in the provided file.");
	    }
	}
}
