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
own tooling:

* PKCS#11: generate with `eth_generateAccount`. To use an existing key on SoftHSM, import it with `softhsm2-util`,
  labelled with the account's EIP-55 checksummed address, which is how signare finds the key:
    ```console
    softhsm2-util --import <key.pem> --slot <slot> --label <checksummed_address> --id <hex_id> --pin <pin>
    ```
  `<key.pem>` is the secp256k1 private key in PKCS#8 PEM form. A hardware HSM uses its vendor's key import procedure,
  labelling both the public and the private key object the same way.
* Azure Key Vault: create the key in the vault and reference it from the slot configuration, as described in
  [how to configure an AKV](../user-guides/how-to-configure-akv.md).
* Local Key Vault: generate with `eth_generateAccount`. An existing key cannot be loaded; use SoftHSM for that.
