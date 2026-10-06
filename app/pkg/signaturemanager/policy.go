package signaturemanager

// HardwareKeysOnly is the deployment-wide rule, set from `hsmmodules.hardwareKeysOnly`, that refuses the
// keys signare could otherwise hold or accept in software: the Local Key Vault refuses to hold or use
// keys, and the Azure Key Vault adapter refuses keys the vault does not report as HSM-held. A PKCS#11
// library is trusted as configured.
type HardwareKeysOnly bool
