package org.example;

import java.security.*;

public class Bob {
    private final KeyPair identity_key_pair;
    PublicKey identity_key;
    private KeyPair ephemeral_key_pair;
    PublicKey ephemeral_key;
    private final KeyPair signed_prekey_pair;
    PublicKey signed_prekey;

    private final KeyPair one_time_prekey_pair;
    PublicKey one_time_prekey;
    byte[] prekey_signature;
    byte[] secret_key;
    byte[] associated_data;
    State state;

    Bob() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        this.identity_key_pair = Crypto.generate_dh();
        this.identity_key = identity_key_pair.getPublic();
        this.ephemeral_key_pair = Crypto.generate_dh();
        this.ephemeral_key = ephemeral_key_pair.getPublic();
        this.signed_prekey_pair = Crypto.generate_dh();
        this.signed_prekey = signed_prekey_pair.getPublic();
        this.one_time_prekey_pair = Crypto.generate_dh();
        this.one_time_prekey = one_time_prekey_pair.getPublic();
        //this.prekey_signature = Crypto.sign(this.identity_key_pair, this.signed_prekey_pair.getPublic().getEncoded());
        this.state = new State(Crypto.generate_dh());
    }

    public void x3dh(Alice alice) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] dh1 = Crypto.dh(this.signed_prekey_pair, alice.identity_key);
        byte[] dh2 = Crypto.dh(this.identity_key_pair, alice.ephemeral_key);
        byte[] dh3 = Crypto.dh(this.ephemeral_key_pair, alice.ephemeral_key);
        byte[] dh4 = Crypto.dh(this.one_time_prekey_pair, alice.ephemeral_key);
        byte[] sk1 = Crypto.concat(dh1, dh2);
        byte[] sk2 = Crypto.concat(dh3, dh4);
        byte[] sk = Crypto.concat(sk1, sk2);
        this.secret_key = Crypto.kdf(sk);
        this.associated_data = Crypto.concat(alice.identity_key.getEncoded(), this.identity_key.getEncoded());
        this.ephemeral_key_pair = null;
    }
}
