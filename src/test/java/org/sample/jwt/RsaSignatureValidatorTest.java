package org.sample.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.RsaSignatureValidator;
import io.jsonwebtoken.impl.crypto.RsaSigner;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.*;
import java.util.Random;

import static junit.framework.TestCase.assertTrue;

/**
 * Created by leif on 12/13/17.
 */
@RunWith(SpringJUnit4ClassRunner.class)
public class RsaSignatureValidatorTest {

	@Test
	public void testSignSuccessful() {
		final Random rng = new Random();
		KeyPairGenerator keyGenerator = null;
		try {
        	keyGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        PrivateKey privateKey = kp.getPrivate();

        byte[] bytes = new byte[16];
        rng.nextBytes(bytes);

        RsaSigner signer = new RsaSigner(SignatureAlgorithm.RS512, privateKey);
        byte[] out1 = signer.sign(bytes);

        byte[] out2 = signer.sign(bytes);

        assertTrue(MessageDigest.isEqual(out1, out2));
    }

    @Test
	public void testDoVerifyWithInvalidKeyException() {

		final Random rng = new Random();
		KeyPairGenerator keyGenerator = null;
		try {
			keyGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		keyGenerator.initialize(1024);

		KeyPair kp = keyGenerator.genKeyPair();
		PublicKey publicKey = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();

		String msg = "foo";
		final InvalidKeyException ex = new InvalidKeyException(msg);

		RsaSignatureValidator v = new RsaSignatureValidator(SignatureAlgorithm.RS256, publicKey);


		byte[] bytes = new byte[16];
		byte[] signature = new byte[16];
		rng.nextBytes(bytes);
		rng.nextBytes(signature);

		assertTrue(v.isValid(bytes, signature));

	}
}
