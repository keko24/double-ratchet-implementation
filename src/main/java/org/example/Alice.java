package org.example;

import java.security.*;

public class Alice {
    private final KeyPair identity_key_pair;
    final PublicKey identity_key;
    private KeyPair ephemeral_key_pair;
    PublicKey ephemeral_key;
    byte[] secret_key;
    byte[] associated_data;
    State state;

    Alice() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        this.identity_key_pair = Crypto.generate_dh();
        this.identity_key = this.identity_key_pair.getPublic();
        this.ephemeral_key_pair = Crypto.generate_dh();
        this.ephemeral_key = this.ephemeral_key_pair.getPublic();
        this.state = new State();
    }

    public void x3dh(Bob bob) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
//        if (!Crypto.verify(bob.identity_key, bob.signed_prekey.getEncoded(), bob.prekey_signature)) {
//            System.out.println("Signature verification failed.");
//            return;
//        }
        byte[] dh1 = Crypto.dh(this.identity_key_pair, bob.signed_prekey);
        byte[] dh2 = Crypto.dh(this.ephemeral_key_pair, bob.identity_key);
        byte[] dh3 = Crypto.dh(this.ephemeral_key_pair, bob.ephemeral_key);
        byte[] dh4 = Crypto.dh(this.ephemeral_key_pair, bob.one_time_prekey);
        byte[] sk1 = Crypto.concat(dh1, dh2);
        byte[] sk2 = Crypto.concat(dh3, dh4);
        byte[] sk = Crypto.concat(sk1, sk2);
        this.secret_key = Crypto.kdf(sk);
        this.associated_data = Crypto.concat(this.identity_key_pair.getPublic().getEncoded(), bob.identity_key.getEncoded());
        this.ephemeral_key_pair = null;
    }
}
