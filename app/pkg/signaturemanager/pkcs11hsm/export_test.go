package pkcs11hsm

// IgnoreKeyProtection makes sm generate keys without CKA_SENSITIVE and CKA_EXTRACTABLE in the template,
// standing in for a token that ignores them, so the read-back can be tested against a real token.
func IgnoreKeyProtection(sm *PKCS11HSMSignatureManager) {
	sm.privateKeyProtection = nil
}
