use std::str::FromStr;
use std::{fs::File, io::Read};

use bitcoin::{
    consensus::Encodable,
    ecdsa,
    hex::{Case, DisplayHex},
    key::{PrivateKey, PublicKey, Secp256k1},
    secp256k1::Message,
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Address, Amount,
    Denomination::Satoshi,
    Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use electrum_client::{Client, ElectrumApi};

pub fn generate_address(public_key: String) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the public key
    let public_key = PublicKey::from_str(&public_key)?;

    Address::p2wpkh(&public_key, Network::Regtest).map(|a| {
        println!("Address: {}", a);
    })?;

    Ok(())
}

pub fn create_transaction(
    destination_address: &str,
    prevout: &str,
    amount: &str,
    electrum_client: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest_address = Address::from_str(destination_address)?
        .require_network(Network::Regtest)
        .expect("Regtest address");
    let prevout = OutPoint::from_str(prevout).expect("Invalid outpoint");
    let amount = Amount::from_str_in(amount, Satoshi).expect("Invalid amount");

    let prev_tx = electrum_client
        .transaction_get(&prevout.txid)
        .expect("Unable to get previous transaction details");
    let utxo_to_spend = prev_tx
        .output
        .get(prevout.vout as usize)
        .expect("Invalid vout");

    // Construct transaction
    let mut tx = Transaction {
        version: Version(2),
        lock_time: bitcoin::absolute::LockTime::from_height(0).unwrap(),
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: amount,
            script_pubkey: dest_address.script_pubkey(),
        }],
    };

    // Compute sighash
    let mut cache = SighashCache::new(tx.clone());
    let sighash = cache.p2wpkh_signature_hash(
        0,
        &utxo_to_spend.script_pubkey,
        utxo_to_spend.value,
        EcdsaSighashType::All,
    )?;
    let msg = Message::from_digest_slice(&sighash[..])?;

    // Load private key
    let secp = Secp256k1::new();
    let mut private_key_str = String::new();
    File::open("key.txt")?.read_to_string(&mut private_key_str)?;
    let private_key = PrivateKey::from_str(&private_key_str)?;
    let public_key = private_key.public_key(&secp).inner;

    let signature = ecdsa::Signature {
        sig: secp.sign_ecdsa(&msg, &private_key.inner),
        hash_ty: EcdsaSighashType::All,
    };
    tx.input[0].witness = Witness::p2wpkh(&signature, &public_key);

    let mut encoded_tx_bytes = Vec::new();
    tx.consensus_encode(&mut encoded_tx_bytes).unwrap();

    // bytes to hex
    println!("Signed tx: {}", encoded_tx_bytes.to_hex_string(Case::Lower));

    Ok(())
}
