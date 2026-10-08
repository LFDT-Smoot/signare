package signaturemanager

// HardwareOnly is the deployment-wide rule, set from `hsmmodules.hardwareOnly`, that refuses the
// keys Signare could otherwise hold or accept in software: the Local Key Vault refuses to hold or use
// keys, and the Azure Key Vault adapter refuses keys the vault does not report as HSM-held. A PKCS#11
// library is trusted as configured.
type HardwareOnly bool
