package org.example;

import java.nio.ByteBuffer;
import java.security.*;

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

public class Crypto {
    static final int KEY_SIZE_BYTES = 32;
    private static final int IV_SIZE_BYTES = 16;
    private static final int AUTH_KEY_SIZE_BYTES = 32;
    private static final int MAC_SIZE_BYTES = 32;

    Crypto() {}

    public static KeyPair generate_dh() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
        kpg.initialize(paramSpec); // equivalent to kpg.initialize(255)
        // alternatively: kpg = KeyPairGenerator.getInstance("X25519")
        return kpg.generateKeyPair();
    }

    public static byte[] dh(KeyPair dh_pair, PublicKey dh_pub) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("XDH");
        keyAgreement.init(dh_pair.getPrivate());
        keyAgreement.doPhase(dh_pub, true);
        return keyAgreement.generateSecret();
    }

    public static byte[] kdf_rk(byte[] rk, byte[] dh_out) {
        Digest digest = new SHA256Digest();
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);

        hkdf.init(new HKDFParameters(dh_out, rk, "Contextual Information".getBytes()));
        byte[] derivedKeyPair = new byte[2 * dh_out.length];
        hkdf.generateBytes(derivedKeyPair, 0, derivedKeyPair.length);

        return derivedKeyPair;
    }

    public static byte[] kdf_ck(byte[] ck) throws NoSuchAlgorithmException, InvalidKeyException {
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
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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

    public static Header header(byte[] dh_pair, int pn, int n) {
        return new Header(n, pn, dh_pair);
    }

    public static byte[] concat(byte[] ad, byte[] header) {
        byte[] concat = new byte[ad.length + header.length];
        System.arraycopy(ad, 0, concat, 0, ad.length);
        System.arraycopy(header, 0, concat, ad.length, header.length);
        return concat;
    }

    static class AEADAuthenticationException extends Exception {
        public AEADAuthenticationException(String message) {
            super(message);
        }
    }

    public static byte[] HKDF(byte[] mk) {
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

    public static byte[] sign(KeyPair keyPair, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("EdDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsaVerify = Signature.getInstance("EdDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(data);
        return ecdsaVerify.verify(signature);
    }

    public static byte[] kdf(byte[] key_material) {
        byte[] F = new byte[KEY_SIZE_BYTES];
        Arrays.fill(F, (byte) 0xFF);
        byte[] input_key_material = concat(F, key_material);
        Digest digest = new SHA256Digest();
        byte[] salt = new byte[digest.getDigestSize()]; // Zero-filled byte sequence
        byte[] info = "MyProtocolMaybeIDK".getBytes();

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        hkdf.init(new HKDFParameters(input_key_material, salt, info));
        byte[] hkdfOutput = new byte[KEY_SIZE_BYTES];
        hkdf.generateBytes(hkdfOutput, 0, hkdfOutput.length);

        return hkdfOutput;
    }

}