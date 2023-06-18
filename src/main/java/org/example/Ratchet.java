package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;

public class Ratchet {
    private final Crypto crypto;
    public Ratchet(Crypto crypto) {
        this.crypto = crypto;
    }

    public void initializeAlice(State state, Key sk, PublicKey dh_pub) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        state.sending_ratchet_key = crypto.generate_dh();
        state.receiving_ratchet_key = dh_pub;
        byte[] secret = crypto.dh(state.sending_ratchet_key, state.receiving_ratchet_key);
        byte[] kdf_rk = crypto.kdf_rk(sk.getEncoded(), secret);
        state.root_key = Arrays.copyOfRange(kdf_rk, 0, crypto.KEY_SIZE_BYTES);
        state.sending_chain_key = Arrays.copyOfRange(kdf_rk, crypto.KEY_SIZE_BYTES, crypto.KEY_SIZE_BYTES * 2);
        state.receiving_chain_key = null;
        state.message_number_sending = 0;
        state.message_number_receiving = 0;
        state.number_of_messages_in_previous_sending_chain = 0;
        state.message_keys_skipped = new HashMap<>();
    }

    public void initializeBob(State state, Key sk, KeyPair bob_dh_key_pair) {
        state.sending_ratchet_key = bob_dh_key_pair;
        state.receiving_ratchet_key = null;
        state.root_key = sk.getEncoded();
        state.sending_chain_key = null;
        state.receiving_chain_key = null;
        state.message_number_sending = 0;
        state.message_number_receiving = 0;
        state.number_of_messages_in_previous_sending_chain = 0;
        state.message_keys_skipped = new HashMap<>();
    }

    public Pair<Header, byte[]> ratchetEncrypt(State state, byte[] plaintext, byte[] associated_data) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] temp = crypto.kdf_ck(state.sending_chain_key);
        state.sending_chain_key = Arrays.copyOfRange(temp, 0, crypto.KEY_SIZE_BYTES);
        byte[] message_key = Arrays.copyOfRange(temp, crypto.KEY_SIZE_BYTES, crypto.KEY_SIZE_BYTES * 2);
        byte[] dh_pair = new byte[64];
        System.arraycopy(state.sending_ratchet_key.getPublic().getEncoded(), 0, dh_pair, 0, 32);
        System.arraycopy(state.sending_ratchet_key.getPrivate().getEncoded(), 0, dh_pair, 32, 32);
        Header header = crypto.header(dh_pair, state.number_of_messages_in_previous_sending_chain, state.message_number_sending);
        state.message_number_sending++;
        byte[] ciphertext = crypto.encrypt(message_key, plaintext, associated_data);
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
        byte[] temp = crypto.kdf_ck(state.receiving_chain_key);
        state.receiving_chain_key = Arrays.copyOfRange(temp, 0, crypto.KEY_SIZE_BYTES);
        byte[] message_key = Arrays.copyOfRange(temp, crypto.KEY_SIZE_BYTES, crypto.KEY_SIZE_BYTES * 2);
        state.message_number_receiving++;
        return crypto.decrypt(message_key, ciphertext, associated_data);
    }

    public byte[] trySkippedMessages(State state, Header header, byte[] ciphertext, byte[] associated_data) throws InvalidAlgorithmParameterException, Crypto.AEADAuthenticationException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Pair<byte[], Integer> header_pair = new Pair<>(header.dh, header.n);
        if (state.message_keys_skipped.containsKey(header_pair)) {
            byte[] message_key = state.message_keys_skipped.get(header_pair);
            state.message_keys_skipped.remove(header_pair);
            return crypto.decrypt(message_key, ciphertext, associated_data);
        }
        return null;
    }

    public void skipMessageKeys(State state, int until) throws Exception {
        if (state.message_number_receiving + crypto.MAX_SKIP > until) {
            throw new Exception("Too many messages to skip");
        }
        if (state.receiving_chain_key == null) {
            while (state.message_number_receiving < until) {
                byte[] temp = crypto.kdf_ck(state.root_key);
                state.root_key = Arrays.copyOfRange(temp, 0, crypto.KEY_SIZE_BYTES);
                state.receiving_chain_key = Arrays.copyOfRange(temp, crypto.KEY_SIZE_BYTES, crypto.KEY_SIZE_BYTES * 2);
                state.message_number_receiving++;
            }
        }
    }

    public void DHRatchet(State state, Header header) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
        state.number_of_messages_in_previous_sending_chain = state.message_number_sending;
        state.message_number_sending = 0;
        state.message_number_receiving = 0;
        state.receiving_ratchet_key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(header.dh));
        byte[] dh = crypto.dh(state.sending_ratchet_key, state.receiving_ratchet_key);
        byte[] temp = crypto.kdf_rk(state.root_key, dh);
        state.root_key = Arrays.copyOfRange(temp, 0, crypto.KEY_SIZE_BYTES);
        state.sending_chain_key = Arrays.copyOfRange(temp, crypto.KEY_SIZE_BYTES, crypto.KEY_SIZE_BYTES * 2);
        state.sending_ratchet_key = crypto.generate_dh();
        byte[] tmp = crypto.kdf_rk(state.root_key, dh);
        state.root_key = Arrays.copyOfRange(tmp, 0, crypto.KEY_SIZE_BYTES);
        state.sending_chain_key = Arrays.copyOfRange(tmp, crypto.KEY_SIZE_BYTES, crypto.KEY_SIZE_BYTES * 2);
    }
}
