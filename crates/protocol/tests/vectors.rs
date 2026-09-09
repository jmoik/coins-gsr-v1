use coins_crypto::G1;
use coins_gsr_protocol::{
    Account, AccountState, Collection, Deposit, OutPoint, apply_collection, caboose_script_pubkey,
    encode_active_state, encode_genesis_state,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    keys: [String; 3],
    balances: [u64; 3],
    nonces: [u32; 3],
    bridge_id: String,
    account_root: String,
    genesis_state: String,
    active_state: String,
    genesis_caboose_spk: String,
    active_caboose_spk: String,
    collection_statement: String,
}

fn bytes<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded).unwrap().try_into().unwrap()
}

#[test]
fn shared_protocol_vectors_match_rust_encoder() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../../../tests/protocol_vectors.json")).unwrap();
    assert!(!vectors.is_empty());

    for vector in vectors {
        let state = AccountState {
            accounts: std::array::from_fn(|index| Account {
                key: G1(bytes(&vector.keys[index])),
                balance: vector.balances[index],
                nonce: vector.nonces[index],
            }),
        };
        let root = state.root();
        assert_eq!(root, bytes(&vector.account_root));

        let genesis = encode_genesis_state(&root);
        let bridge_id = bytes(&vector.bridge_id);
        let active = encode_active_state(&bridge_id, &root);
        assert_eq!(genesis, bytes(&vector.genesis_state));
        assert_eq!(active, bytes(&vector.active_state));
        assert_eq!(
            caboose_script_pubkey(&genesis),
            bytes(&vector.genesis_caboose_spk)
        );
        assert_eq!(
            caboose_script_pubkey(&active),
            bytes(&vector.active_caboose_spk)
        );

        let collection = apply_collection(&Collection {
            bridge_id,
            bridge_prevout: OutPoint {
                txid: [0x31; 32],
                vout: 0,
            },
            old_state: state,
            old_backing: 201_007,
            deposits: [
                Deposit {
                    outpoint: OutPoint {
                        txid: [0x41; 32],
                        vout: 1,
                    },
                    value: 5_000,
                    recipient_id: 0,
                },
                Deposit {
                    outpoint: OutPoint {
                        txid: [0x52; 32],
                        vout: 2,
                    },
                    value: 6_000,
                    recipient_id: 1,
                },
            ],
        })
        .unwrap();
        assert_eq!(
            collection.statement,
            hex::decode(&vector.collection_statement).unwrap()
        );
    }
}
