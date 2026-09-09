use ark_bn254::Fr;
use coins_crypto::{G1, SecretKey};
use coins_gsr_protocol::{
    Account, AccountState, Collection, Deposit, OutPoint, apply_collection, caboose_script_pubkey,
    encode_active_state, encode_genesis_state,
};
use serde::Serialize;

#[derive(Serialize)]
struct Vector {
    id: &'static str,
    keys: Vec<String>,
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

fn main() {
    let keys = [11_u64, 12, 13].map(|value| SecretKey(Fr::from(value)));
    let public = keys.map(|key| G1(key.public_key()));
    let balances = [120_000, 80_000, 7];
    let nonces = [2, 3, 4];
    let state = AccountState {
        accounts: std::array::from_fn(|index| Account {
            key: public[index],
            balance: balances[index],
            nonce: nonces[index],
        }),
    };
    let bridge_id = std::array::from_fn(|index| index as u8);
    let root = state.root();
    let genesis = encode_genesis_state(&root);
    let active = encode_active_state(&bridge_id, &root);
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
    let vector = Vector {
        id: "state_encoding_v1",
        keys: public.into_iter().map(|key| hex::encode(key.0)).collect(),
        balances,
        nonces,
        bridge_id: hex::encode(bridge_id),
        account_root: hex::encode(root),
        genesis_state: hex::encode(genesis),
        active_state: hex::encode(active),
        genesis_caboose_spk: hex::encode(caboose_script_pubkey(&genesis)),
        active_caboose_spk: hex::encode(caboose_script_pubkey(&active)),
        collection_statement: hex::encode(collection.statement),
    };
    println!("{}", serde_json::to_string_pretty(&vec![vector]).unwrap());
}
