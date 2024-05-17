# Tari Transactions WASM wrapper

## Overview

This is a WASM library wrapper for (Tari Core Transactions)[https://github.com/tari-project/tari/tree/development/base_layer/core]

Features of this library include:

- Identifying outputs created by one-sided transactions that belongs to this Tari wallet
- No really, that's it

## Compiling to WebAssembly

To build the WebAssembly module, go to `/tari_transaction_services` and use this command:

    $ wasm-pack build .

To generate a module for use in node.js, use this command:

    $ wasm-pack build --target nodejs -d tari_transactions_wasm_js .

To run the wasm bindings unit tests, use this command:

    $ wasm-pack test --node

Note: Node v10+ is needed for the WASM

## Usage

- `scan_output_for_one_sided_payment`
  
  Scans a transaction output for a one-sided payment belonging to this wallet. The output is scanned for a one-sided 
  payment using the provided wallet secret key and known script keys. The output is decrypted and verified using the 
  shared secret derived from the wallet secret key and the sender's offset public key.
 

- `scan_output_for_one_sided_payment_ledger`
  
  Scans a transaction output for a one-sided payment belonging to this 
  ledger wallet. The output is scanned for a one-sided payment using the provided wallet secret view key and wallet 
  public spend key. The output is decrypted and verified using the shared secret derived from the wallet secret key 
  and the sender's offset public key. 

## Making changes

This library needs to be regenerated and committed on an as-needed basis. As the parent repo references the compiled 
package directly.