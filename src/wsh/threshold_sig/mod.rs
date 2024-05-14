use std::{error::Error, fs::File, io::Read, str::FromStr};

use bitcoin::{
    consensus::Encodable,
    ecdsa,
    hex::{DisplayHex, FromHex},
    key::Secp256k1,
    psbt::Psbt,
    secp256k1::{All, Message},
    sighash::SighashCache,
    Address, Amount,
    Denomination::Satoshi,
    EcdsaSighashType, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use miniscript::{psbt::PsbtExt, Descriptor, DescriptorPublicKey};

pub fn generate_descriptor(
    alice_pubkey: &str,
    bob_pubkey: &str,
    charlie_pubkey: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Spend policy string: {}",
        generate_descriptor_internal(alice_pubkey, bob_pubkey, charlie_pubkey)?
    );

    Ok(())
}

fn generate_descriptor_internal(
    alice_pubkey: &str,
    bob_pubkey: &str,
    charlie_pubkey: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut keys = vec![
        DescriptorPublicKey::from_str(alice_pubkey)?,
        DescriptorPublicKey::from_str(bob_pubkey)?,
        DescriptorPublicKey::from_str(charlie_pubkey)?,
    ];
    keys.sort_by_key(|k| k.to_string());

    let joined_keys: String = keys
        .iter()
        .map(|key| key.to_string())
        .collect::<Vec<String>>()
        .join(",");

    Ok(format!("wsh(sortedmulti(2,{}))", joined_keys))
}

pub fn generate_address(descriptor_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Address: {}", generate_address_internal(descriptor_str)?);
    Ok(())
}

fn generate_address_internal(descriptor_str: &str) -> Result<Address, Box<dyn std::error::Error>> {
    let descriptor = Descriptor::<PublicKey>::from_str(descriptor_str)?;
    let address = descriptor.address(bitcoin::Network::Regtest).unwrap();

    Ok(address)
}

pub fn create_signed_psbt(
    secp: &Secp256k1<All>,
    utxo_to_spend: &TxOut,
    descriptor_str: &str,
    destination_address: &str,
    prevout: OutPoint,
    amount: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest_address = Address::from_str(destination_address)?
        .require_network(Network::Regtest)
        .expect("Regtest address");
    let amount = Amount::from_str_in(amount, Satoshi).expect("Invalid amount");
    let descriptor = Descriptor::<PublicKey>::from_str(descriptor_str)?;

    // Load private key
    let mut private_key_str = String::new();
    File::open("key.txt")?.read_to_string(&mut private_key_str)?;
    let private_key = PrivateKey::from_str(&private_key_str)?;

    println!(
        "Psbt: {}",
        create_signed_psbt_internal(
            &secp,
            utxo_to_spend,
            private_key,
            descriptor,
            dest_address,
            prevout,
            amount
        )?
        .serialize_hex()
    );

    Ok(())
}

fn create_signed_psbt_internal(
    secp: &Secp256k1<All>,
    utxo_to_spend: &TxOut,
    private_key: PrivateKey,
    descriptor: Descriptor<PublicKey>,
    destination_address: Address,
    prevout: OutPoint,
    amount: Amount,
) -> Result<Psbt, Box<dyn Error>> {
    let unsigned_tx = Transaction {
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
            script_pubkey: destination_address.script_pubkey(),
        }],
    };
    let witness_script = descriptor.explicit_script()?;

    // Sign wsh output
    let mut cache = SighashCache::new(unsigned_tx.clone());
    let sighash = cache.p2wsh_signature_hash(
        0,
        &witness_script,
        utxo_to_spend.value,
        EcdsaSighashType::All,
    )?;
    let msg = Message::from_digest_slice(&sighash[..])?;

    let signature = ecdsa::Signature {
        sig: secp.sign_ecdsa(&msg, &private_key.inner),
        hash_ty: EcdsaSighashType::All,
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    psbt.inputs[0].witness_utxo = Some(utxo_to_spend.clone());
    psbt.inputs[0]
        .partial_sigs
        .insert(private_key.public_key(&secp), signature);

    psbt.inputs[0].witness_script = Some(witness_script);

    Ok(psbt)
}

/// Combines two PSBTs given as hex-encoded strings.
pub fn combine_psbts(
    secp: &Secp256k1<All>,
    psbt_1_hex: &str,
    psbt_2_hex: &str,
) -> Result<(), Box<dyn Error>> {
    // Decode the hex string into bytes and deserialize into Psbt
    let psbt_1_bytes = Vec::from_hex(psbt_1_hex)?;
    let host_psbt = Psbt::deserialize(&psbt_1_bytes)?;

    let psbt_2_bytes = Vec::from_hex(psbt_2_hex)?;
    let second_psbt = Psbt::deserialize(&psbt_2_bytes)?;

    let finalized_psbt = combine_psbts_internal(&secp, host_psbt, second_psbt)?;

    // Serialize the combined PSBT back to hex for display or further use
    println!("Combined PSBT: {}", finalized_psbt.serialize_hex());
    let mut encoded_tx_bytes = Vec::new();
    let finalized_tx = finalized_psbt.extract_tx()?;
    finalized_tx
        .consensus_encode(&mut encoded_tx_bytes)
        .unwrap();
    println!(
        "Transaction to broadcast: {}",
        encoded_tx_bytes.to_lower_hex_string()
    );

    Ok(())
}

fn combine_psbts_internal(
    secp: &Secp256k1<All>,
    mut psbt_1: Psbt,
    psbt_2: Psbt,
) -> Result<Psbt, Box<dyn Error>> {
    psbt_1.combine(psbt_2)?;

    let finalized_psbt = psbt_1.finalize(secp).expect("Unable to finalize PSBT");
    Ok(finalized_psbt)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        key::Secp256k1, Address, Amount, Denomination::Satoshi, OutPoint, PrivateKey, PublicKey,
        ScriptBuf, TxOut,
    };
    use miniscript::Descriptor;

    use crate::wsh::threshold_sig::{
        combine_psbts_internal, create_signed_psbt_internal, generate_address_internal,
    };

    use super::generate_descriptor_internal;

    #[test]
    fn test_2of3() {
        // Generate things about our private/public keypairs
        let secp = Secp256k1::new();
        let alice_sk = PrivateKey::from_str("L1SrewR4YKr1CvX33vK9z3HqdVEWMzZL3nG66nLsJZeFvZDH4Gp4")
            .expect("Alice's private key private key parsing failed.");
        let alice_pk = alice_sk.public_key(&secp).inner;

        let bob_sk = PrivateKey::from_str("KyyKrSNF8fE8ML2JpF8gRq3qST3fDpcPEKaBk27Q22k7E9AH4FkL")
            .expect("Bob's private key private key parsing failed.");
        let bob_pk = bob_sk.public_key(&secp).inner;

        let charlie_sk =
            PrivateKey::from_str("KwYVip7ord3y86qjLY8ca9mRWcf7bE5sjavVbgKQcQUAKUYMW1sk")
                .expect("Charlie's private key parsing failed.");
        let charlie_pk = charlie_sk.public_key(&secp).inner;

        // Ensure our output descriptor, and conversely our address, is as expected
        let descriptor_str = generate_descriptor_internal(
            &alice_pk.to_string(),
            &bob_pk.to_string(),
            &charlie_pk.to_string(),
        )
        .expect("Descriptor generation failed");
        assert_eq!(descriptor_str, "wsh(sortedmulti(2,02c843041d74e80d603de1c59fe9644cef04ded85076970d1141bcf04977397bde,02e3a6822881384e821a121bef8da55eaa3f7b905899d672bcaf353b54575db3ec,038000c4aa5c2ae6edeb3e350d10ef1c4167ae204c9fddb08cea5cc4ac699c00f6))");

        let address =
            generate_address_internal(&descriptor_str).expect("Address generation failed");
        assert_eq!(
            address.to_string(),
            "bcrt1q8wmjmkf0qgshwmqnlptn5jfw4yhwhfc0ve49cg9u0m24ayee6llshuc5g9"
        );

        // Attempt to send some bitcoin to an address.
        // Identify the output, and outpoint we want to spend
        let output_to_spend_spk = ScriptBuf::from_hex(
            "00203bb72dd92f0221776c13f8573a492ea92eeba70f666a5c20bc7ed55e9339d7ff",
        )
        .expect("Invalid script pub key");
        let output_to_spend = TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: output_to_spend_spk,
        };
        let prevout = OutPoint::from_str(
            "bf210c79258b733a0b5076c96fc26eef206f63789a14719db9552212b5e0ed8d:1",
        )
        .expect("Invalid outpoint");

        // Address we want to spend to, with amount.
        let destination_address = Address::from_str("bcrt1qt72nlqdrlj3yrlslx5sx7ltle337gflz5s23xu")
            .expect("Unable to parse address")
            .assume_checked();

        let amount = Amount::from_str_in("50000", Satoshi).expect("Invalid amount");

        let descriptor =
            Descriptor::<PublicKey>::from_str(&descriptor_str).expect("Error deriving descriptor");

        let psbt_1 = create_signed_psbt_internal(
            &secp,
            &output_to_spend,
            alice_sk,
            descriptor.clone(),
            destination_address.clone(),
            prevout,
            amount,
        )
        .expect("Alice PSBT");

        let psbt_2 = create_signed_psbt_internal(
            &secp,
            &output_to_spend,
            bob_sk,
            descriptor,
            destination_address,
            prevout,
            amount,
        )
        .expect("Bob PSBT");

        let composed_psbt = combine_psbts_internal(&secp, psbt_1, psbt_2).expect("Combined PSBT");

        assert_eq!(composed_psbt.serialize_hex(), "70736274ff01005202000000018dede0b5122255b99d71149a78636f20ef6ec26fc976500b3a738b25790c21bf0100000000ffffffff0150c30000000000001600145f953f81a3fca241fe1f35206f7d7fcc63e427e2000000000001012ba0860100000000002200203bb72dd92f0221776c13f8573a492ea92eeba70f666a5c20bc7ed55e9339d7ff0108fdfd000400483045022100a617cd8cd32e83478ac4939a70d2a68802d5a60c447e6eb72efac26d217e5a3802204b7c5b45b4827a7669694626a41cef90f222e00b73545874fe4d2dcbc00e701601473044022005a56b5498eb1d7f7a1009c69e0f801b4cd84477e349d35aa3448e8244baae6f02204b388e47e681dc6b00ae8f903c58d50a6d9c27e614534e9658890f36e9a78f270169522102c843041d74e80d603de1c59fe9644cef04ded85076970d1141bcf04977397bde2102e3a6822881384e821a121bef8da55eaa3f7b905899d672bcaf353b54575db3ec21038000c4aa5c2ae6edeb3e350d10ef1c4167ae204c9fddb08cea5cc4ac699c00f653ae0000")
    }
}
