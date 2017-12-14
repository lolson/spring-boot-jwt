package org.sample.jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.security.*;

@Component
public class KeyGenerator {

	public KeyGenerator() {
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		keyPairGenerator.initialize(1024);
		KeyPair kp = keyPairGenerator.genKeyPair();
		setPublicKey(kp.getPublic());
		setPrivateKey(kp.getPrivate());
	}

	private PrivateKey privateKey;
	private PublicKey publicKey;

	private void createPrivateKey() { // Get this from a SecurityContoller
		//https://github.com/jwtk/jjwt/blob/master/src/test/groovy/io/jsonwebtoken/impl/crypto/RsaSignatureValidatorTest.groovy
//		KeyPairGenerator keyPairGenerator = null;
//		try {
//			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}
//		keyPairGenerator.initialize(1024);
//		KeyPair kp = keyPairGenerator.genKeyPair();
//		setPublicKey(kp.getPublic());
//		setPrivateKey(kp.getPrivate());
		// see RsaSignatueValidator that takes public key
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
}
