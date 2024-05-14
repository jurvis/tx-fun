use std::{fs::File, io::Read, str::FromStr};

use bitcoin::{
    consensus::Encodable,
    hex::{Case, DisplayHex},
    key::{Keypair, Secp256k1, TapTweak},
    secp256k1::{All, Message},
    sighash::{Prevouts, SighashCache},
    taproot, Address, Amount,
    Denomination::Satoshi,
    Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use electrum_client::{Client, ElectrumApi};

pub fn generate_address(
    secp: &Secp256k1<All>,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the public key
    let public_key = PublicKey::from_str(public_key)?;
    let internal_key: XOnlyPublicKey = public_key.into();

    // Let rust-bitcoin handle tweaking
    let addr = Address::p2tr(secp, internal_key, None, Network::Regtest);
    println!("Address: {}", addr);

    Ok(())
}

pub fn create_transaction(
    secp: &Secp256k1<All>,
    electrum_client: &Client,
    destination_address: &str,
    prevout: &str,
    amount: &str,
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

    let mut unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
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
    let binding = vec![utxo_to_spend];
    let prevouts = Prevouts::All(&binding);

    let mut cache = SighashCache::new(&unsigned_tx);
    let sighash =
        cache.taproot_key_spend_signature_hash(0, &prevouts, bitcoin::TapSighashType::Default)?;
    let msg = Message::from_digest_slice(&sighash[..])?;

    // Sign
    // Load private key
    let mut private_key_str = String::new();
    File::open("key.txt")?.read_to_string(&mut private_key_str)?;
    let private_key = PrivateKey::from_str(&private_key_str)?;
    let keypair = Keypair::from_secret_key(secp, &private_key.inner);

    let tweaked_key_pair = keypair.tap_tweak(secp, None);
    let signature = taproot::Signature {
        sig: secp.sign_schnorr(&msg, &tweaked_key_pair.to_inner()),
        hash_ty: bitcoin::TapSighashType::Default,
    };

    // Sanity check
    secp.verify_schnorr(
        &signature.sig,
        &msg,
        &tweaked_key_pair.to_inner().x_only_public_key().0,
    )
    .unwrap();

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    unsigned_tx.input[0].witness = witness;

    let mut encoded_tx_bytes = Vec::new();
    unsigned_tx.consensus_encode(&mut encoded_tx_bytes).unwrap();

    // bytes to hex
    println!("Signed tx: {}", encoded_tx_bytes.to_hex_string(Case::Lower));

    Ok(())
}
