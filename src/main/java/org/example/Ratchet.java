package org.example;

import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;

public class Ratchet {
    final int MAX_SKIP = 256;

    public Ratchet() throws Exception {
        Alice alice = new Alice();
        Bob bob = new Bob();
        alice.x3dh(bob);
        bob.x3dh(alice);
        initializeBob(bob.state, bob.secret_key, bob.state.sending_ratchet_key);
        initializeAlice(alice.state, alice.secret_key, bob.state.sending_ratchet_key.getPublic());
        byte[] plaintext = "Hello, Bob!".getBytes();
        System.out.println("Plaintext: " + new String(plaintext));
        Pair<Header, byte[]> ciphertext = ratchetEncrypt(alice.state, plaintext, alice.associated_data);
        System.out.println("Ciphertext: " + new String(ciphertext.second));
        byte[] plaintext2 = ratchetDecrypt(bob.state, ciphertext.first, ciphertext.second, bob.associated_data);
        System.out.println("Plaintext: " + new String(plaintext2));
        byte[] plaintextA = "Hello, Alice!".getBytes();
        System.out.println("Plaintext: " + new String(plaintextA));
        Pair<Header, byte[]> ciphertext1 = ratchetEncrypt(alice.state, plaintextA, alice.associated_data);
        System.out.println("Ciphertext: " + new String(ciphertext1.second));
        byte[] plaintext21 = ratchetDecrypt(bob.state, ciphertext1.first, ciphertext1.second, bob.associated_data);
        System.out.println("Plaintext: " + new String(plaintext21));
    }

    public static void initializeAlice(State state, byte[] sk, PublicKey bob_dh_pub) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException {
        state.sending_ratchet_key = Crypto.generate_dh();
        state.receiving_ratchet_key = bob_dh_pub;
        byte[] secret = Crypto.dh(state.sending_ratchet_key, state.receiving_ratchet_key);
        byte[] kdf_rk = Crypto.kdf_rk(sk, secret);
        state.root_key = Arrays.copyOfRange(kdf_rk, 0, Crypto.KEY_SIZE_BYTES);
        state.sending_chain_key = Arrays.copyOfRange(kdf_rk, Crypto.KEY_SIZE_BYTES, Crypto.KEY_SIZE_BYTES * 2);
        state.receiving_chain_key = null;
        state.message_number_sending = 0;
        state.message_number_receiving = 0;
        state.number_of_messages_in_previous_sending_chain = 0;
        state.message_keys_skipped = new HashMap<>();
    }

    public void initializeBob(State state, byte[] sk, KeyPair bob_dh_key_pair) {
        state.sending_ratchet_key = bob_dh_key_pair;
        state.receiving_ratchet_key = null;
        state.root_key = sk;
        state.sending_chain_key = null;
        state.receiving_chain_key = null;
        state.message_number_sending = 0;
        state.message_number_receiving = 0;
        state.number_of_messages_in_previous_sending_chain = 0;
        state.message_keys_skipped = new HashMap<>();
    }

    public Pair<Header, byte[]> ratchetEncrypt(State state, byte[] plaintext, byte[] associated_data) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] temp = Crypto.kdf_ck(state.sending_chain_key);
        state.sending_chain_key = Arrays.copyOfRange(temp, 0, Crypto.KEY_SIZE_BYTES);
        byte[] message_key = Arrays.copyOfRange(temp, Crypto.KEY_SIZE_BYTES, Crypto.KEY_SIZE_BYTES * 2);
        byte[] dh_pair = new byte[64];
        System.arraycopy(state.sending_ratchet_key.getPublic().getEncoded(), 0, dh_pair, 0, 32);
        System.arraycopy(state.sending_ratchet_key.getPrivate().getEncoded(), 0, dh_pair, 32, 32);
        Header header = Crypto.header(dh_pair, state.number_of_messages_in_previous_sending_chain, state.message_number_sending);
        state.message_number_sending++;
        byte[] ciphertext = Crypto.encrypt(message_key, plaintext, associated_data);
        return new Pair<>(header, ciphertext);
    }

    public byte[] ratchetDecrypt(State state, Header header, byte[] ciphertext, byte[] associated_data) throws Exception {
        byte[] plaintext = trySkippedMessages(state, header, ciphertext, associated_data);
        if (plaintext != null) {
            return plaintext;
        }
        if (!Arrays.equals(header.dh, state.receiving_chain_key)) {
            skipMessageKeys(state, header.pn);
            DHRatchet(state, header);
        }
        skipMessageKeys(state, header.n);
        byte[] temp = Crypto.kdf_ck(state.receiving_chain_key);
        state.receiving_chain_key = Arrays.copyOfRange(temp, 0, Crypto.KEY_SIZE_BYTES);
        byte[] message_key = Arrays.copyOfRange(temp, Crypto.KEY_SIZE_BYTES, Crypto.KEY_SIZE_BYTES * 2);
        state.message_number_receiving++;
        return Crypto.decrypt(message_key, ciphertext, associated_data);
    }

    public byte[] trySkippedMessages(State state, Header header, byte[] ciphertext, byte[] associated_data) throws InvalidAlgorithmParameterException, Crypto.AEADAuthenticationException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Pair<byte[], Integer> header_pair = new Pair<>(header.dh, header.n);
        if (state.message_keys_skipped.containsKey(header_pair)) {
            byte[] message_key = state.message_keys_skipped.get(header_pair);
            state.message_keys_skipped.remove(header_pair);
            return Crypto.decrypt(message_key, ciphertext, associated_data);
        }
        return null;
    }

    public void skipMessageKeys(State state, int until) throws Exception {
        if (state.message_number_receiving + MAX_SKIP < until) {
            throw new Exception("Too many messages to skip");
        }
        if (state.receiving_chain_key == null) {
            while (state.message_number_receiving < until) {
                byte[] temp = Crypto.kdf_ck(state.root_key);
                state.root_key = Arrays.copyOfRange(temp, 0, Crypto.KEY_SIZE_BYTES);
                state.receiving_chain_key = Arrays.copyOfRange(temp, Crypto.KEY_SIZE_BYTES, Crypto.KEY_SIZE_BYTES * 2);
                state.message_number_receiving++;
            }
        }
    }

    public void DHRatchet(State state, Header header) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
        state.number_of_messages_in_previous_sending_chain = state.message_number_sending;
        state.message_number_sending = 0;
        state.message_number_receiving = 0;

        byte[] keyBytes = Arrays.copyOfRange(header.dh, 0, 32);
        X25519PublicKeyParameters publicKeyParameters = new X25519PublicKeyParameters(keyBytes, 0);

// If you need PublicKey object
        byte[] x509bytes = new byte[44];
        System.arraycopy(new byte[] { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00 }, 0, x509bytes, 0, 12);
        System.arraycopy(keyBytes, 0, x509bytes, 12, keyBytes.length);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509bytes);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        state.receiving_ratchet_key = kf.generatePublic(keySpec);

        byte[] dh = Crypto.dh(state.sending_ratchet_key, state.receiving_ratchet_key);
        byte[] temp = Crypto.kdf_rk(state.root_key, dh);
        state.root_key = Arrays.copyOfRange(temp, 0, Crypto.KEY_SIZE_BYTES);
        state.receiving_chain_key = Arrays.copyOfRange(temp, Crypto.KEY_SIZE_BYTES, Crypto.KEY_SIZE_BYTES * 2);
        state.sending_ratchet_key = Crypto.generate_dh();
        byte[] tmp = Crypto.kdf_rk(state.root_key, dh);
        state.root_key = Arrays.copyOfRange(tmp, 0, Crypto.KEY_SIZE_BYTES);
        state.sending_chain_key = Arrays.copyOfRange(tmp, Crypto.KEY_SIZE_BYTES, Crypto.KEY_SIZE_BYTES * 2);
    }
}
