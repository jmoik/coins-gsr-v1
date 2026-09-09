//! Canonical bounded Coins + GSR v1 state-transition model.

use coins_crypto::{G1, G2, verify};
use coins_types::{NATIVE_TOKEN_ID, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ACCOUNT_COUNT: usize = 3;
pub const TRANSFER_SENDER_ID: u32 = 0;
pub const WITHDRAWAL_ACCOUNT_ID: u32 = 1;
pub const FEE_ACCOUNT_ID: u32 = 2;
pub const RESERVE: u64 = 1_000;
pub const CABOOSE_VALUE: u64 = 330;
pub const STATE_MAGIC: &[u8; 7] = b"UTXOLIN";
pub const STATE_VERSION: u8 = 1;
pub const PROTOCOL_VERSION: u8 = 1;

const ACCOUNT_ROOT_DOMAIN: &[u8] = b"coins-gsr-v1/accounts\0";
const STATEMENT_DOMAIN: &[u8] = b"coins-gsr-v1/statement/regtest\0";
const TRANSFER_AUTH_DOMAIN: &[u8] = b"coins-gsr-v1/transfer-auth/regtest\0";
const WITHDRAWAL_DOMAIN: &[u8] = b"coins-gsr-v1/withdrawal/regtest\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAccountKey,
    DuplicateAccountKey,
    InvalidBacking,
    InvalidDeposit,
    DepositOrder,
    InvalidRecipient,
    Arithmetic,
    UnsupportedTransfer,
    InvalidTransferSignature,
    InvalidScopedTransferSignature,
    InvalidWithdrawal,
    InvalidWithdrawalSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub key: G1,
    pub balance: u64,
    pub nonce: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    pub accounts: [Account; ACCOUNT_COUNT],
}

impl AccountState {
    pub fn zero(keys: [G1; ACCOUNT_COUNT]) -> Result<Self, Error> {
        let state = Self {
            accounts: keys.map(|key| Account {
                key,
                balance: 0,
                nonce: 0,
            }),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), Error> {
        for (index, account) in self.accounts.iter().enumerate() {
            let point = account.key.to_affine().ok_or(Error::InvalidAccountKey)?;
            if point.infinity || G1::from_affine(&point) != account.key {
                return Err(Error::InvalidAccountKey);
            }
            if self.accounts[..index]
                .iter()
                .any(|previous| previous.key == account.key)
            {
                return Err(Error::DuplicateAccountKey);
            }
        }
        Ok(())
    }

    pub fn root(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(ACCOUNT_ROOT_DOMAIN);
        for (id, account) in self.accounts.iter().enumerate() {
            hash.update((id as u32).to_le_bytes());
            hash.update(account.key.0);
            hash.update(account.balance.to_le_bytes());
            hash.update(account.nonce.to_le_bytes());
        }
        hash.finalize().into()
    }

    pub fn backing(&self) -> Result<u64, Error> {
        self.accounts.iter().try_fold(RESERVE, |sum, account| {
            sum.checked_add(account.balance).ok_or(Error::Arithmetic)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    pub fn encode(&self) -> [u8; 36] {
        let mut encoded = [0_u8; 36];
        encoded[..32].copy_from_slice(&self.txid);
        encoded[32..].copy_from_slice(&self.vout.to_le_bytes());
        encoded
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    pub outpoint: OutPoint,
    pub value: u64,
    pub recipient_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub bridge_id: [u8; 32],
    pub bridge_prevout: OutPoint,
    pub old_state: AccountState,
    pub old_backing: u64,
    pub deposits: [Deposit; 2],
}

#[derive(Clone, Debug)]
pub struct Settlement {
    pub bridge_id: [u8; 32],
    pub bridge_prevout: OutPoint,
    pub old_state: AccountState,
    pub old_backing: u64,
    pub transfer: Transaction,
    pub transfer_signature: G2,
    pub scoped_transfer_signature: G2,
    pub withdrawal_nonce: u32,
    pub withdrawal_amount: u64,
    pub withdrawal_destination: Vec<u8>,
    pub withdrawal_signature: G2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub new_state: AccountState,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub new_backing: u64,
    pub statement: Vec<u8>,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    CollectTwo = 1,
    TransferWithdraw = 2,
}

fn require_backing(state: &AccountState, supplied: u64) -> Result<(), Error> {
    if state.backing()? != supplied {
        return Err(Error::InvalidBacking);
    }
    Ok(())
}

fn statement_prefix(
    action: Action,
    bridge_id: &[u8; 32],
    bridge_prevout: &OutPoint,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    old_backing: u64,
    new_backing: u64,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(160);
    output.extend_from_slice(STATEMENT_DOMAIN);
    output.push(PROTOCOL_VERSION);
    output.push(action as u8);
    output.extend_from_slice(bridge_id);
    output.extend_from_slice(&bridge_prevout.encode());
    output.extend_from_slice(old_root);
    output.extend_from_slice(new_root);
    output.extend_from_slice(&old_backing.to_le_bytes());
    output.extend_from_slice(&new_backing.to_le_bytes());
    output
}

pub fn apply_collection(input: &Collection) -> Result<Transition, Error> {
    input.old_state.validate()?;
    require_backing(&input.old_state, input.old_backing)?;

    if input.deposits[0].outpoint.encode() >= input.deposits[1].outpoint.encode() {
        return Err(Error::DepositOrder);
    }

    let mut new_state = input.old_state.clone();
    for deposit in &input.deposits {
        if deposit.value == 0 {
            return Err(Error::InvalidDeposit);
        }
        let account = new_state
            .accounts
            .get_mut(deposit.recipient_id as usize)
            .ok_or(Error::InvalidRecipient)?;
        account.balance = account
            .balance
            .checked_add(deposit.value)
            .ok_or(Error::Arithmetic)?;
    }

    let deposit_total = input.deposits.iter().try_fold(0_u64, |sum, deposit| {
        sum.checked_add(deposit.value).ok_or(Error::Arithmetic)
    })?;
    let new_backing = input
        .old_backing
        .checked_add(deposit_total)
        .ok_or(Error::Arithmetic)?;
    require_backing(&new_state, new_backing)?;

    let old_root = input.old_state.root();
    let new_root = new_state.root();
    let mut statement = statement_prefix(
        Action::CollectTwo,
        &input.bridge_id,
        &input.bridge_prevout,
        &old_root,
        &new_root,
        input.old_backing,
        new_backing,
    );
    for deposit in &input.deposits {
        statement.extend_from_slice(&deposit.outpoint.encode());
        statement.extend_from_slice(&deposit.value.to_le_bytes());
        statement.extend_from_slice(&deposit.recipient_id.to_le_bytes());
        statement.extend_from_slice(
            &input.old_state.accounts[deposit.recipient_id as usize]
                .key
                .0,
        );
    }

    Ok(Transition {
        new_state,
        old_root,
        new_root,
        new_backing,
        statement,
    })
}

pub fn scoped_transfer_message(bridge_id: &[u8; 32], native_message: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(TRANSFER_AUTH_DOMAIN.len() + 64);
    message.extend_from_slice(TRANSFER_AUTH_DOMAIN);
    message.extend_from_slice(bridge_id);
    message.extend_from_slice(&Sha256::digest(native_message));
    message
}

pub fn withdrawal_message(
    bridge_id: &[u8; 32],
    nonce: u32,
    amount: u64,
    destination: &[u8],
) -> Result<Vec<u8>, Error> {
    if amount == 0 || destination.len() != 34 || destination[..2] != [0x51, 0x20] {
        return Err(Error::InvalidWithdrawal);
    }
    let mut message = Vec::with_capacity(WITHDRAWAL_DOMAIN.len() + 82);
    message.extend_from_slice(WITHDRAWAL_DOMAIN);
    message.extend_from_slice(bridge_id);
    message.extend_from_slice(&WITHDRAWAL_ACCOUNT_ID.to_le_bytes());
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&amount.to_le_bytes());
    encode_compact_size(destination.len() as u64, &mut message);
    message.extend_from_slice(destination);
    Ok(message)
}

pub fn apply_settlement(input: &Settlement) -> Result<Transition, Error> {
    input.old_state.validate()?;
    require_backing(&input.old_state, input.old_backing)?;

    let transfer = &input.transfer;
    if transfer.sender_id != TRANSFER_SENDER_ID
        || transfer.recipient_pk != input.old_state.accounts[WITHDRAWAL_ACCOUNT_ID as usize].key
        || transfer.token_id != NATIVE_TOKEN_ID
    {
        return Err(Error::UnsupportedTransfer);
    }

    let mut new_state = input.old_state.clone();
    let sender = &input.old_state.accounts[TRANSFER_SENDER_ID as usize];
    let native_message = transfer.message_to_sign(sender.nonce);
    if !verify(&sender.key, &native_message, &input.transfer_signature) {
        return Err(Error::InvalidTransferSignature);
    }
    let scoped_message = scoped_transfer_message(&input.bridge_id, &native_message);
    if !verify(
        &sender.key,
        &scoped_message,
        &input.scoped_transfer_signature,
    ) {
        return Err(Error::InvalidScopedTransferSignature);
    }

    let transfer_debit = u64::from(transfer.amount)
        .checked_add(u64::from(transfer.fee))
        .ok_or(Error::Arithmetic)?;
    new_state.accounts[TRANSFER_SENDER_ID as usize].balance = sender
        .balance
        .checked_sub(transfer_debit)
        .ok_or(Error::Arithmetic)?;
    new_state.accounts[TRANSFER_SENDER_ID as usize].nonce =
        sender.nonce.checked_add(1).ok_or(Error::Arithmetic)?;
    new_state.accounts[WITHDRAWAL_ACCOUNT_ID as usize].balance = new_state.accounts
        [WITHDRAWAL_ACCOUNT_ID as usize]
        .balance
        .checked_add(u64::from(transfer.amount))
        .ok_or(Error::Arithmetic)?;
    new_state.accounts[FEE_ACCOUNT_ID as usize].balance = new_state.accounts
        [FEE_ACCOUNT_ID as usize]
        .balance
        .checked_add(u64::from(transfer.fee))
        .ok_or(Error::Arithmetic)?;

    let withdrawing = new_state.accounts[WITHDRAWAL_ACCOUNT_ID as usize];
    if input.withdrawal_nonce != withdrawing.nonce {
        return Err(Error::InvalidWithdrawal);
    }
    let withdrawal_message = withdrawal_message(
        &input.bridge_id,
        input.withdrawal_nonce,
        input.withdrawal_amount,
        &input.withdrawal_destination,
    )?;
    if !verify(
        &withdrawing.key,
        &withdrawal_message,
        &input.withdrawal_signature,
    ) {
        return Err(Error::InvalidWithdrawalSignature);
    }
    new_state.accounts[WITHDRAWAL_ACCOUNT_ID as usize].balance = withdrawing
        .balance
        .checked_sub(input.withdrawal_amount)
        .ok_or(Error::Arithmetic)?;
    new_state.accounts[WITHDRAWAL_ACCOUNT_ID as usize].nonce =
        withdrawing.nonce.checked_add(1).ok_or(Error::Arithmetic)?;

    let new_backing = input
        .old_backing
        .checked_sub(input.withdrawal_amount)
        .ok_or(Error::Arithmetic)?;
    require_backing(&new_state, new_backing)?;

    let old_root = input.old_state.root();
    let new_root = new_state.root();
    let mut statement = statement_prefix(
        Action::TransferWithdraw,
        &input.bridge_id,
        &input.bridge_prevout,
        &old_root,
        &new_root,
        input.old_backing,
        new_backing,
    );
    statement.extend_from_slice(&Sha256::digest(&native_message));
    statement.extend_from_slice(&Sha256::digest(&scoped_message));
    statement.extend_from_slice(&Sha256::digest(&withdrawal_message));
    statement.extend_from_slice(&input.withdrawal_amount.to_le_bytes());
    encode_compact_size(input.withdrawal_destination.len() as u64, &mut statement);
    statement.extend_from_slice(&input.withdrawal_destination);

    Ok(Transition {
        new_state,
        old_root,
        new_root,
        new_backing,
        statement,
    })
}

pub fn encode_genesis_state(account_root: &[u8; 32]) -> [u8; 41] {
    let mut state = [0_u8; 41];
    state[..7].copy_from_slice(STATE_MAGIC);
    state[7] = STATE_VERSION;
    state[8] = 0;
    state[9..].copy_from_slice(account_root);
    state
}

pub fn encode_active_state(bridge_id: &[u8; 32], account_root: &[u8; 32]) -> [u8; 73] {
    let mut state = [0_u8; 73];
    state[..7].copy_from_slice(STATE_MAGIC);
    state[7] = STATE_VERSION;
    state[8] = 1;
    state[9..41].copy_from_slice(bridge_id);
    state[41..].copy_from_slice(account_root);
    state
}

pub fn caboose_script_pubkey(state: &[u8]) -> [u8; 34] {
    let state_hash = Sha256::digest(state);
    let mut witness_script = [0_u8; 38];
    witness_script[0] = 0x6a;
    witness_script[1] = 0x24;
    witness_script[2..34].copy_from_slice(&state_hash);
    let script_hash = Sha256::digest(witness_script);
    let mut script_pubkey = [0_u8; 34];
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x20;
    script_pubkey[2..].copy_from_slice(&script_hash);
    script_pubkey
}

pub fn encode_compact_size(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=0xfc => output.push(value as u8),
        0xfd..=0xffff => {
            output.push(0xfd);
            output.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0xfe);
            output.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            output.push(0xff);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use coins_crypto::{SecretKey, sign};

    fn keys() -> ([SecretKey; 3], [G1; 3]) {
        let secrets = [11_u64, 12, 13].map(|value| SecretKey(Fr::from(value)));
        let publics = secrets.map(|secret| G1(secret.public_key()));
        (secrets, publics)
    }

    fn deposits() -> [Deposit; 2] {
        [
            Deposit {
                outpoint: OutPoint {
                    txid: [0x11; 32],
                    vout: 1,
                },
                value: 120_000,
                recipient_id: 0,
            },
            Deposit {
                outpoint: OutPoint {
                    txid: [0x22; 32],
                    vout: 2,
                },
                value: 80_000,
                recipient_id: 1,
            },
        ]
    }

    #[test]
    fn collection_credits_exact_deposits_and_preserves_identity_free_root() {
        let (_, public) = keys();
        let old_state = AccountState::zero(public).unwrap();
        let input = Collection {
            bridge_id: [0x42; 32],
            bridge_prevout: OutPoint {
                txid: [0x33; 32],
                vout: 0,
            },
            old_state: old_state.clone(),
            old_backing: RESERVE,
            deposits: deposits(),
        };
        let transition = apply_collection(&input).unwrap();
        assert_eq!(transition.new_state.accounts[0].balance, 120_000);
        assert_eq!(transition.new_state.accounts[1].balance, 80_000);
        assert_eq!(transition.new_state.accounts[2].balance, 0);
        assert_eq!(transition.new_backing, 201_000);

        let mut other_id = input.clone();
        other_id.bridge_id[0] ^= 1;
        assert_eq!(
            apply_collection(&other_id).unwrap().new_root,
            transition.new_root
        );
        assert_ne!(
            apply_collection(&other_id).unwrap().statement,
            transition.statement
        );
    }

    #[test]
    fn collection_rejects_order_amount_recipient_and_backing_errors() {
        let (_, public) = keys();
        let base = Collection {
            bridge_id: [0x42; 32],
            bridge_prevout: OutPoint {
                txid: [0x33; 32],
                vout: 0,
            },
            old_state: AccountState::zero(public).unwrap(),
            old_backing: RESERVE,
            deposits: deposits(),
        };

        let mut bad = base.clone();
        bad.deposits.swap(0, 1);
        assert_eq!(apply_collection(&bad), Err(Error::DepositOrder));
        bad = base.clone();
        bad.deposits[0].value = 0;
        assert_eq!(apply_collection(&bad), Err(Error::InvalidDeposit));
        bad = base.clone();
        bad.deposits[0].recipient_id = 3;
        assert_eq!(apply_collection(&bad), Err(Error::InvalidRecipient));
        bad = base;
        bad.old_backing += 1;
        assert_eq!(apply_collection(&bad), Err(Error::InvalidBacking));
    }

    #[test]
    fn settlement_validates_native_and_bridge_scoped_authorizations() {
        let (secret, public) = keys();
        let mut old_state = AccountState::zero(public).unwrap();
        old_state.accounts[0].balance = 120_000;
        old_state.accounts[1].balance = 80_000;
        let transfer = Transaction {
            sender_id: 0,
            recipient_pk: public[1],
            token_id: NATIVE_TOKEN_ID,
            amount: 50_000,
            fee: 1,
        };
        let native_message = transfer.message_to_sign(0);
        let bridge_id = [0x42; 32];
        let withdrawal_destination = [vec![0x51, 0x20], vec![0x77; 32]].concat();
        let withdrawal =
            withdrawal_message(&bridge_id, 0, 60_000, &withdrawal_destination).unwrap();
        let input = Settlement {
            bridge_id,
            bridge_prevout: OutPoint {
                txid: [0x44; 32],
                vout: 0,
            },
            old_backing: old_state.backing().unwrap(),
            old_state,
            transfer,
            transfer_signature: sign(&secret[0], &native_message),
            scoped_transfer_signature: sign(
                &secret[0],
                &scoped_transfer_message(&bridge_id, &native_message),
            ),
            withdrawal_nonce: 0,
            withdrawal_amount: 60_000,
            withdrawal_destination,
            withdrawal_signature: sign(&secret[1], &withdrawal),
        };

        let transition = apply_settlement(&input).unwrap();
        assert_eq!(transition.new_state.accounts[0].balance, 69_999);
        assert_eq!(transition.new_state.accounts[0].nonce, 1);
        assert_eq!(transition.new_state.accounts[1].balance, 70_000);
        assert_eq!(transition.new_state.accounts[1].nonce, 1);
        assert_eq!(transition.new_state.accounts[2].balance, 1);
        assert_eq!(transition.new_backing, 141_000);

        let mut replay = input.clone();
        replay.bridge_id[0] ^= 1;
        replay.withdrawal_signature = sign(
            &secret[1],
            &withdrawal_message(
                &replay.bridge_id,
                replay.withdrawal_nonce,
                replay.withdrawal_amount,
                &replay.withdrawal_destination,
            )
            .unwrap(),
        );
        assert_eq!(
            apply_settlement(&replay),
            Err(Error::InvalidScopedTransferSignature)
        );
    }

    #[test]
    fn settlement_rejects_signature_payout_and_arithmetic_mutations() {
        let (secret, public) = keys();
        let mut old_state = AccountState::zero(public).unwrap();
        old_state.accounts[0].balance = 100_000;
        let transfer = Transaction {
            sender_id: 0,
            recipient_pk: public[1],
            token_id: 0,
            amount: 50_000,
            fee: 1,
        };
        let native_message = transfer.message_to_sign(0);
        let bridge_id = [0x42; 32];
        let destination = [vec![0x51, 0x20], vec![0x77; 32]].concat();
        let withdrawal = withdrawal_message(&bridge_id, 0, 40_000, &destination).unwrap();
        let base = Settlement {
            bridge_id,
            bridge_prevout: OutPoint {
                txid: [0x44; 32],
                vout: 0,
            },
            old_backing: old_state.backing().unwrap(),
            old_state,
            transfer,
            transfer_signature: sign(&secret[0], &native_message),
            scoped_transfer_signature: sign(
                &secret[0],
                &scoped_transfer_message(&bridge_id, &native_message),
            ),
            withdrawal_nonce: 0,
            withdrawal_amount: 40_000,
            withdrawal_destination: destination,
            withdrawal_signature: sign(&secret[1], &withdrawal),
        };

        let mut bad = base.clone();
        bad.transfer_signature.0[0] ^= 1;
        assert_eq!(apply_settlement(&bad), Err(Error::InvalidTransferSignature));
        bad = base.clone();
        bad.withdrawal_destination[3] ^= 1;
        assert_eq!(
            apply_settlement(&bad),
            Err(Error::InvalidWithdrawalSignature)
        );
        bad = base;
        bad.withdrawal_amount = 60_000;
        let message = withdrawal_message(
            &bad.bridge_id,
            bad.withdrawal_nonce,
            bad.withdrawal_amount,
            &bad.withdrawal_destination,
        )
        .unwrap();
        bad.withdrawal_signature = sign(&secret[1], &message);
        assert_eq!(apply_settlement(&bad), Err(Error::Arithmetic));
    }

    #[test]
    fn state_and_caboose_encodings_have_fixed_shapes() {
        let root = [0x55; 32];
        let bridge_id = [0x66; 32];
        let genesis = encode_genesis_state(&root);
        let active = encode_active_state(&bridge_id, &root);
        assert_eq!(genesis.len(), 41);
        assert_eq!(active.len(), 73);
        assert_eq!(&genesis[..9], b"UTXOLIN\x01\x00");
        assert_eq!(&active[..9], b"UTXOLIN\x01\x01");
        assert_ne!(
            caboose_script_pubkey(&genesis),
            caboose_script_pubkey(&active)
        );
    }

    #[test]
    fn compact_size_boundaries_are_canonical() {
        for (value, expected) in [
            (0xfc, vec![0xfc]),
            (0xfd, vec![0xfd, 0xfd, 0x00]),
            (0x1_0000, vec![0xfe, 0x00, 0x00, 0x01, 0x00]),
            (
                0x1_0000_0000,
                vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
        ] {
            let mut encoded = Vec::new();
            encode_compact_size(value, &mut encoded);
            assert_eq!(encoded, expected);
        }
    }
}
