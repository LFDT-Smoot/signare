# Supported Signing Modules

This document provides a list of supported signing modules that can be configured.

The target audience of this document is system administrators interested in understanding how to configure a signing module.

## Available signing modules

* PKCS#11: Signare integrates with any HSM that exposes the PKCS#11 (Cryptoki) interface, including on-premise hardware HSMs. Testing is carried out against SoftHSM, a software implementation of a cryptographic store accessible through PKCS#11.
* Azure Key Vault: Microsoft Azure service to encrypt keys and small secrets using HSMs. A fully managed, cloud-native option that removes the operational overhead of running your own hardware.
* Local Key Vault: A local implementation designed to store private keys in database. Ideal for local testing and development, but not recommended for production, since keys are stored in software rather than dedicated hardware.

Check our [open api spec documentation](./openapi-spec.md) on how to properly configure a new signing module.

## Where keys come from

Signare never accepts a private key through its API, so key material does not pass through requests, proxies or logs
on its way in. A key either originates inside the module, through `eth_generateAccount`, or is loaded with the module's
own tooling.

* On PKCS#11, generate keys with `eth_generateAccount`. To use an existing key on SoftHSM, import it with
  `softhsm2-util`. A key held as 64 hex characters, the form `eth_importAccount` took, converts to PKCS#8 PEM on the way
  in.
    ```console
    dir=$(mktemp -d -p /dev/shm)   # private to you and held in memory, so the key never reaches disk
    read -rs HEX                   # the 64 hex characters, read without echo so the key stays out of shell history
    echo "302e0201010420${HEX}a00706052b8104000a" | xxd -r -p | openssl pkey -inform DER -out "$dir/key.pem"
    unset HEX
    softhsm2-util --import "$dir/key.pem" --slot <slot> --label <checksummed_address> --id "$(printf '%016x' "$(date +%s%N)")"
    rm -rf "$dir"
    ```
    * `--label` must be the account's EIP-55 checksummed address, which is how signare finds the key. Any Ethereum
      tool can derive it, for example Foundry's `cast wallet address --interactive`, which prompts for the key.
    * Keep the key and the PIN off every command line, because other local users can read a running command's
      arguments and some hosts audit them. `read` and `echo` are shell builtins, so the key reaches `xxd` through a
      pipe, and `softhsm2-util` prompts for the user PIN, twice, when `--pin` is left out.
    * Keep the PEM file in a fresh directory that only you can open, on memory-backed storage such as `/dev/shm`. A file
      written to an ordinary disk can survive `rm`, and an old file in the working directory keeps its permissions
      when it is overwritten.
    * `--id` should be 8 bytes, as above. Signare reads it as the key's creation time in nanoseconds to order
      `eth_accounts`, and any other length sorts the key first.
    * Do not pass `--no-public-key`, because signare lists keys through the public key object.

  A hardware HSM uses its vendor's key import procedure, labelling both the public and the private key object the
  same way.
* On Azure Key Vault, create the key in the vault and reference it from the slot configuration, as described in
  [how to configure an AKV](../user-guides/how-to-configure-akv.md).
* On a Local Key Vault, generate keys with `eth_generateAccount`. An existing key cannot be loaded, so use SoftHSM for
  that.
