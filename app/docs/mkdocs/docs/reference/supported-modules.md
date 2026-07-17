# Supported Signing Modules

This document provides a list of supported signing modules that can be configured.

The target audience of this document is system administrators interested in understanding how to configure a signing module.

## Available signing modules

* PKCS#11: Signare integrates with any HSM that exposes the PKCS#11 (Cryptoki) interface, including on-premise hardware HSMs. Testing is carried out against SoftHSM, a software implementation of a cryptographic store accessible through PKCS#11.
* Azure Key Vault: Microsoft Azure service to encrypt keys and small secrets using HSMs. A fully managed, cloud-native option that removes the operational overhead of running your own hardware.
* Local Key Vault: A local implementation designed to store private keys in database. Ideal for local testing and development, but not recommended for production, since keys are stored in software rather than dedicated hardware.

Check our [open api spec documentation](./openapi-spec.md) on how to properly configure a new signing module.    