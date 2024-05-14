# Tx Fun

Harmless transaction fun with Bitcoin regtest.

## Initial Setup

1. Clone `jurvis/regtest-tools`: https://github.com/jurvis/regtest-tools
2. Run `just bootstrap` then `just start` on the `regtest-tools` repository.
3. Run `cargo install --path .` to install the `tx-fun` binary to your system path.
4. Check that you can open `localhost:5000` in your browser and see 100 blocks mined.

## P2WPKH Demo

1. Run `tx-fun generate-key` to get started. The public key will be printed to the console. Copy this public key for the next step.
2. Run `tx-fun generate-address <public-key>` to generate a P2WPKH address.
3. For your sanity, run `alias bcr="bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=local123"` to make interacting with `bitcoind` easier.
4. Run `bcr sendtoaddress <your address> <your send amount | 0.001 is good>` to send some funds to your address.
5. Now, let's spend it! First, generate an address to send to. We can use one from our `bitcoind` instance: `bcr getnewaddress`. Then, run `tx-fun wpkh sign-transaction <your newly-generated address> <prevout> <your send amount | 50000>` to spend the funds. The txid will be printed to the console.
6. Go to `localhost:5000` and paste the txid into the search bar. You should see your transaction!

## P2TR Demo

Kind of the same as P2WPKH.

## P2WSH Demo

We implement a P2WSH transaction with a 2-of-3 multisig script.

To play with this, you'd need to get three people together. Then, each person will have to:

1. Generate a keypair with `tx-fun generate-key`.
2. Get their public keys from `tx-fun pubkey`
3. Share their public keys with the other two people.

Then, individually:

1. Generate a P2WSH address with `tx-fun generate-descriptor <pubkey1> <pubkey2> <pubkey3>`.
2. Using the output descriptor, generate an address with `tx-fun generate-address <descriptor>`.

Check that all participants generate the same descriptor and address.

Now that we have an address, we need to send funds to it. Use `bcr sendtoaddress <address> <amount>` to send funds to the address. bitcoin-cli should return a txid.

Next, we get to the fun part. Let's try and spend it!

As usual, you would need to specify the prevout of the input you are trying to spend. You'd need to go to `localhost:5000` and find the txid of the transaction you just sent and identify the output to spend.

Then, assign two people to run the following command: `tx-fun psbt <descriptor> <destination address> <prevout> <amount>` to produce a PSBT with your signature on it.

## Ideas

1. Update to maintain two sets of keys – one for an external and one for change.
2. Update interface to accept multiple prevouts
