use bitcoin::secp256k1::rand::rngs::OsRng;

use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::All;
use bitcoin::Network;

use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

use bitcoin::key::Secp256k1;

use std::path::Path;

pub fn generate_key(secp: &Secp256k1<All>, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Step 0: abort if we already created a key
    let path = Path::new(path);
    if path.exists() {
        panic!("Key already created. To print pubkey, run `tx-fun pubkey`");
    }

    // Generate keypair
    let (sk, pk) = secp.generate_keypair(&mut OsRng);
    let priv_key = PrivateKey::new(sk, Network::Regtest);
    println!("Public key: {}", pk);

    // Write WIF privkey to key.txt
    let mut file = File::create(path).expect("Unable to create file");
    file.write_all(priv_key.to_wif().as_bytes())
        .expect("Unable to write data");

    Ok(())
}

pub fn read_pubkey(secp: &Secp256k1<All>, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);
    if path.exists() {
        let mut private_key_str = String::new();
        File::open(path)?.read_to_string(&mut private_key_str)?;
        let private_key = PrivateKey::from_str(&private_key_str)?;
        let public_key = private_key.public_key(secp).inner;
        println!("Public key is: {}", public_key);
    } else {
        println!("No key found at path: {}", path.display());
    }

    Ok(())
}
