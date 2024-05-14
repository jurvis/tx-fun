use std::str::FromStr;

use bitcoin::{key::Secp256k1, OutPoint};
use clap::{Parser, Subcommand};
use electrum_client::ElectrumApi;

mod common;
mod tr;
mod wpkh;
mod wsh;

#[derive(Clone, Parser)]
#[clap()]
pub struct Cli {
    /// URL for the Electrum node
    #[clap(short, long, default_value = "tcp://localhost:60401")]
    electrum: String,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Clone, Subcommand)]
enum Commands {
    /// P2wpkh Tools
    Wpkh {
        #[clap(subcommand)]
        command: WpkhCommands,
    },
    Wsh {
        #[clap(subcommand)]
        command: WshCommands,
    },
    Tr {
        #[clap(subcommand)]
        command: TrCommands,
    },
    Keygen {
        /// The path to write the key to
        #[clap(default_value = "key.txt")]
        path: String,
    },
    Pubkey {
        /// The path to read the key from
        #[clap(default_value = "key.txt")]
        path: String,
    },
}

#[derive(Clone, Subcommand)]
enum WpkhCommands {
    /// Generate a new address
    GenerateAddress {
        /// The public key to generate the address from
        public_key: String,
    },
    /// Create a signed transaction
    SignTransaction {
        /// The destination address
        destination: String,
        /// The previous output
        prevout: String,
        /// The amount to send
        amount: String,
    },
}

#[derive(Clone, Subcommand)]
enum TrCommands {
    /// Generate a new address
    GenerateAddress {
        /// The public key to generate the address from
        public_key: String,
    },
    /// Create a signed transaction
    SignTransaction {
        /// The destination address
        destination: String,
        /// The previous output
        prevout: String,
        /// The amount to send
        amount: String,
    },
}

#[derive(Clone, Subcommand)]
enum WshCommands {
    GenerateDescriptor {
        /// The public key to generate the address from
        public_keys: Vec<String>,
    },
    GenerateAddress {
        /// The descriptor to generate the address from
        descriptor: String,
    },
    SignPsbt {
        /// The descriptor to generate the witness script
        descriptor: String,
        /// The destination address
        destination: String,
        /// The previous output
        prevout: String,
        /// The amount to send
        amount: String,
    },
    CombinePsbts {
        /// The PSBTs to combine
        psbts: Vec<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let secp = Secp256k1::new();
    let electrum_client = electrum_client::Client::new(&cli.electrum)?;

    match cli.command {
        Commands::Keygen { path } => common::keys::generate_key(&secp, &path),
        Commands::Pubkey { path } => common::keys::read_pubkey(&secp, &path),
        Commands::Wpkh { command } => match command {
            WpkhCommands::GenerateAddress { public_key } => wpkh::generate_address(public_key),
            WpkhCommands::SignTransaction {
                destination,
                prevout,
                amount,
            } => wpkh::create_transaction(&destination, &prevout, &amount, &electrum_client),
        },
        Commands::Tr { command } => match command {
            TrCommands::GenerateAddress { public_key } => {
                tr::keyspend::generate_address(&secp, &public_key)
            }
            TrCommands::SignTransaction {
                destination,
                prevout,
                amount,
            } => tr::keyspend::create_transaction(
                &secp,
                &electrum_client,
                &destination,
                &prevout,
                &amount,
            ),
        },
        Commands::Wsh { command } => match command {
            WshCommands::GenerateDescriptor { public_keys } => {
                if public_keys.len() != 3 {
                    panic!("Must provide only 3 public keys!");
                }
                wsh::threshold_sig::generate_descriptor(
                    &public_keys[0],
                    &public_keys[1],
                    &public_keys[2],
                )
            }
            WshCommands::GenerateAddress { descriptor } => {
                wsh::threshold_sig::generate_address(&descriptor)
            }
            WshCommands::SignPsbt {
                descriptor,
                destination,
                prevout,
                amount,
            } => {
                let prevout = OutPoint::from_str(&prevout).expect("Invalid outpoint");
                let prev_tx = electrum_client
                    .transaction_get(&prevout.txid)
                    .expect("Unable to get previous transaction details");
                let utxo_to_spend = prev_tx
                    .output
                    .get(prevout.vout as usize)
                    .expect("Invalid vout");

                wsh::threshold_sig::create_signed_psbt(
                    &secp,
                    &utxo_to_spend,
                    &descriptor,
                    &destination,
                    prevout,
                    &amount,
                )
            }
            WshCommands::CombinePsbts { psbts } => {
                wsh::threshold_sig::combine_psbts(&secp, &psbts[0], &psbts[1])
            }
        },
    }
}
