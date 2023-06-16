package org.example;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class crypto {
    private static final int KEY_SIZE_BYTES = 32;
    private static final int IV_SIZE_BYTES = 16;
    private static final int AUTH_KEY_SIZE_BYTES = 32;
    private static final int MAC_SIZE_BYTES = 32;
    SecureRandom secureRandom;
    crypto() {
        this.secureRandom = new SecureRandom();
    }

    public KeyPair generate_dh() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
        kpg.initialize(paramSpec); // equivalent to kpg.initialize(255)
        // alternatively: kpg = KeyPairGenerator.getInstance("X25519")
        return kpg.generateKeyPair();
    }

    public byte[] dh(KeyPair dh_pair, PublicKey dh_pub) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(dh_pair.getPrivate());
        keyAgreement.doPhase(dh_pub, true);
        return keyAgreement.generateSecret();
    }

    public byte[] kdf_rk(byte[] rk, byte[] dh_out) throws InvalidKeySpecException, NoSuchAlgorithmException {
        Digest digest = new SHA256Digest();
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);

        hkdf.init(new HKDFParameters(dh_out, rk, "Contextual Information".getBytes()));
        byte[] derivedKeyPair = new byte[2 * dh_out.length];
        hkdf.generateBytes(derivedKeyPair, 0, derivedKeyPair.length);

        return derivedKeyPair;
    }

    public byte[] kdf_ck(byte[] ck) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] derivedKeyPair = new byte[2 * ck.length];
        System.arraycopy(derivedKeyPair, 0, calculateHmacSha256(ck, new byte[]{0x01}), 0, ck.length);
        System.arraycopy(derivedKeyPair, ck.length, calculateHmacSha256(ck, new byte[]{0x01}), 0, ck.length);
        return derivedKeyPair;
    }

    public static byte[] encrypt(byte[] mk, byte[] plaintext, byte[] associatedData) throws NoSuchAlgorithmException,
        InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException,
        IllegalBlockSizeException {
        // Generate encryption key, authentication key, and IV using HKDF
        byte[] hkdfOutput = HKDF(mk);
        byte[] encryptionKey = Arrays.copyOfRange(hkdfOutput, 0, KEY_SIZE_BYTES);
        byte[] authKey = Arrays.copyOfRange(hkdfOutput, KEY_SIZE_BYTES, KEY_SIZE_BYTES + AUTH_KEY_SIZE_BYTES);
        byte[] iv = Arrays.copyOfRange(hkdfOutput, KEY_SIZE_BYTES + AUTH_KEY_SIZE_BYTES,
            KEY_SIZE_BYTES + AUTH_KEY_SIZE_BYTES + IV_SIZE_BYTES);

        // Encrypt the plaintext using AES-256 in CBC mode with PKCS#7 padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Calculate HMAC using the authentication key
        byte[] hmacInput = ByteBuffer.allocate(associatedData.length + ciphertext.length).put(associatedData).put(ciphertext).array();
        byte[] hmac = calculateHmacSha256(authKey, hmacInput);

        // Append HMAC to the ciphertext
        return ByteBuffer.allocate(ciphertext.length + MAC_SIZE_BYTES)
            .put(ciphertext)
            .put(hmac)
            .array();
    }

    public static byte[] decrypt(byte[] mk, byte[] ciphertext, byte[] associatedData) throws NoSuchAlgorithmException,
        InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException,
        IllegalBlockSizeException, AEADAuthenticationException {
        // Split ciphertext into encrypted message and HMAC
        byte[] encryptedMessage = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - MAC_SIZE_BYTES);
        byte[] hmac = Arrays.copyOfRange(ciphertext, ciphertext.length - MAC_SIZE_BYTES, ciphertext.length);

        // Generate encryption key, authentication key, and IV using HKDF
        byte[] hkdfOutput = HKDF(mk);
        byte[] encryptionKey = Arrays.copyOfRange(hkdfOutput, 0, KEY_SIZE_BYTES);
        byte[] authKey = Arrays.copyOfRange(hkdfOutput, KEY_SIZE_BYTES, KEY_SIZE_BYTES + AUTH_KEY_SIZE_BYTES);
        byte[] iv = Arrays.copyOfRange(hkdfOutput, KEY_SIZE_BYTES + AUTH_KEY_SIZE_BYTES,
            KEY_SIZE_BYTES + AUTH_KEY_SIZE_BYTES + IV_SIZE_BYTES);

        // Calculate HMAC using the authentication key and associated data
        byte[] hmacInput = ByteBuffer.allocate(associatedData.length + encryptedMessage.length).put(associatedData).put(encryptedMessage).array();
        byte[] calculatedHmac = calculateHmacSha256(authKey, hmacInput);

        // Verify the HMAC
        if (!Arrays.equals(hmac, calculatedHmac)) {
            throw new AEADAuthenticationException("Authentication failed");
        }

        // Decrypt the ciphertext using AES-256 in CBC mode with PKCS#7 padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(encryptedMessage);
    }

    static class AEADAuthenticationException extends Exception {
        public AEADAuthenticationException(String message) {
            super(message);
        }
    }

    private static byte[] HKDF(byte[] mk) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(mk, "AES");
        Digest digest = new SHA256Digest();
        byte[] salt = new byte[digest.getDigestSize()]; // Zero-filled byte sequence
        byte[] info = "application-specific-info".getBytes();

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        hkdf.init(new HKDFParameters(mk, salt, info));
        byte[] hkdfOutput = new byte[KEY_SIZE_BYTES + AUTH_KEY_SIZE_BYTES + IV_SIZE_BYTES];
        hkdf.generateBytes(hkdfOutput, 0, hkdfOutput.length);

        return hkdfOutput;
    }

    private static byte[] calculateHmacSha256(byte[] key, byte[] input) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
        hmacSha256.init(secretKey);
        return hmacSha256.doFinal(input);
    }

}