package org.example;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;

public class State {
    KeyPair sending_ratchet_key;
    PublicKey receiving_ratchet_key;
    byte[] root_key;
    byte[] sending_chain_key;
    byte[] receiving_chain_key;
    int message_number_sending;
    int message_number_receiving;
    int number_of_messages_in_previous_sending_chain;
    Map<Pair<byte[], Integer>, byte[]> message_keys_skipped;

    State() {

    }

    State(KeyPair sending_ratchet_key) {
        this.sending_ratchet_key = sending_ratchet_key;
    }

}
